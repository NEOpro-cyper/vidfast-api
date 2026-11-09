#!/usr/bin/env node
/**
 * Stream Resolver API — standalone single-file server (vidy.st / api.wecollege.net).
 * No framework. Only dependency: node-libcurl (plain Node fetch / system curl can
 * get 403'd by Cloudflare TLS fingerprinting; libcurl passes).
 *
 * Resolution flow (per media):
 *   1. GET  https://api.wecollege.net/seed?mediaId={tmdbId}              -> { seed }
 *   2. GET  https://api.wecollege.net/{server}/sources
 *            ?title={double-url-encoded title}&mediaType=movie|tv&year={year}
 *            &episodeId={ep}&seasonId={season}        (tv only)
 *            &tmdbId={tmdbId}&imdbId={imdbId}&enc=2&seed={seed}   -> encrypted text
 *   3. POST https://enc-dec.app/api/dec-videasy  { text, id, seed }      -> { result }
 *
 * Metadata (title / year / imdbId) is needed for step 2. It is resolved from the
 * TMDB/IMDb id via api.themoviedb.org — set TMDB_API_KEY (v3) or
 * TMDB_ACCESS_TOKEN (v4) — or supplied per request via ?title=&year=&imdbId=
 * (plus &tmdbId= when the path id is an IMDb id).
 *
 * Env:
 *   PORT               listen port (default 3000)
 *   TMDB_API_KEY       TMDB v3 api key
 *   TMDB_ACCESS_TOKEN  TMDB v4 bearer token (preferred over api_key)
 *   VIDY_BASE          override upstream base (default https://api.wecollege.net)
 *   ENCDEC_API         override decryptor base (default https://enc-dec.app/api)
 *   WORKER_URL         proxy prefix applied with ?worker=1
 *   WORKER_URL_EN      encrypting proxy prefix applied with ?data=en
 *   TOKEN_SECRET       aes-256-gcm secret for ?data=en (must match decrypt worker)
 *
 * Endpoints:
 *   GET /api/movie/{tmdbOrImdbId}                   ?server=1|name &worker=1 &data=en
 *   GET /api/tv/{tmdbOrImdbId}/{season}/{episode}   ?server=1|name &worker=1 &data=en
 *   GET /                                           -> info
 *
 * Run:   npm install && node server.js
 */

'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const { Curl } = require('node-libcurl');

/* ----------------------------- config ----------------------------- */

const PORT = Number(process.env.PORT) || 3000;
const VIDY_BASE = process.env.VIDY_BASE || 'https://api.wecollege.net';
const VIDY_REFERER = 'https://vidy.st/';
const VIDY_ORIGIN = 'https://vidy.st';
const ENCDEC_API = process.env.ENCDEC_API || 'https://enc-dec.app/api';
const ENC_VERSION = '2'; // wecollege algorithm version
const TMDB_API = 'https://api.themoviedb.org/3';
const TMDB_API_KEY = process.env.TMDB_API_KEY || '8476a7ab80ad76f0936744df0430e67c';
const TMDB_ACCESS_TOKEN = process.env.TMDB_ACCESS_TOKEN || '';
const WORKER_URL =
  process.env.WORKER_URL || 'https://icy-art-1d5b-movy.ntb7nmytsd.workers.dev/';

// Worker used ONLY for ?data=en (encrypted mode)
const WORKER_URL_EN =
  process.env.WORKER_URL_EN || 'https://noisy-feather-adb6.ryklcd0086.workers.dev/vf';

/* ------------------------ URL encryptor (?data=en) ------------------------ */
// When a request includes ?data=en, the stream url is rewritten as
// `${WORKER_URL_EN}/${encryptedToken}` instead of plain text.
// Token format (must match the SECRET in your decrypt worker):
//   v1.<b64url(iv)>.<b64url(ciphertext+authtag)>
const TOKEN_SECRET =
  process.env.TOKEN_SECRET ||
  'bbef4e4840ab0a33b6c129f0de8b1a6735471c82f43e9babc4adc64c5959a64a';

function b64url(buf) {
  return Buffer.from(buf)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function encryptUrlToken(rawUrl) {
  const key = crypto.createHash('sha256').update(TOKEN_SECRET, 'utf8').digest();
  const iv = crypto
    .createHash('sha256')
    .update('iv:' + rawUrl, 'utf8')
    .digest()
    .subarray(0, 12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(rawUrl, 'utf8'), cipher.final()]);
  return 'v1.' + b64url(iv) + '.' + b64url(Buffer.concat([ct, cipher.getAuthTag()]));
}

const USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36';

const VIDY_HEADERS = [
  'Accept: */*',
  `Origin: ${VIDY_ORIGIN}`,
  `Referer: ${VIDY_REFERER}`,
];

/* Server catalogue — order defines the 1-based ?server=N index.
 *   language      -> appended as &language=… to the sources url (Munich)
 *   altTitleLang  -> use this TMDB translated title when available (Berlin)
 *   filterQuality -> keep only decrypted sources whose quality matches (Austin, Delhi) */
const SERVERS = [
  { path: 'miami',    name: 'Miami',    description: 'Original [May have 4K]' },
  { path: 'boise',    name: 'Boise',    description: 'Original [May have 4K]' },
  { path: 'vegas',    name: 'Vegas',    description: 'Original' },
  { path: 'reno',     name: 'Reno',     description: 'Original' },
  { path: 'oakland',  name: 'Oakland',  description: 'Original' },
  { path: 'seattle',  name: 'Seattle',  description: 'Original' },
  { path: 'phoenix',  name: 'Phoenix',  description: 'Original' },
  { path: 'atlanta',  name: 'Atlanta',  description: 'Original' },
  { path: 'portland', name: 'Portland', description: 'Original' },
  { path: 'austin',   name: 'Austin',   description: 'Original (English audio)', filterQuality: 'English' },
  { path: 'dallas',   name: 'Dallas',   description: 'Original' },
  { path: 'tampa',    name: 'Tampa',    description: 'Original' },
  { path: 'orlando',  name: 'Orlando',  description: 'Original' },
  { path: 'munich',   name: 'Munich',   description: 'German', language: 'german' },
  { path: 'berlin',   name: 'Berlin',   description: 'German (uses German title when available)', altTitleLang: 'de' },
  { path: 'paris',    name: 'Paris',    description: 'French' },
  { path: 'delhi',    name: 'Delhi',    description: 'Hindi', filterQuality: 'Hindi' },
  { path: 'cancun',   name: 'Cancun',   description: 'Spanish' },
];

const METADATA_TTL_MS = 24 * 60 * 60 * 1000; // tmdb title/year/imdb fresh for 24 h
const SEED_CACHE_TTL_MS = 15 * 60 * 1000;    // seed + context fresh for 15 min
const STREAM_CACHE_TTL_MS = 8 * 60 * 1000;   // decrypted sources fresh for 8 min
const REQUEST_TIMEOUT_MS = 20000;
const PROBE_TIMEOUT_MS = 6000;
const FETCH_CONCURRENCY = 6;                 // parallel wecollege/enc-dec requests

/* --------------------------- curl wrapper -------------------------- */
/* NOTE: on POST, POSTFIELDS must always be set ('' is fine) — otherwise
   libcurl registers a read callback that aborts the transfer.          */

function curlRequest(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const curl = new Curl();
    curl.setOpt(Curl.option.URL, url);
    curl.setOpt(Curl.option.FOLLOWLOCATION, true);
    curl.setOpt(Curl.option.USERAGENT, USER_AGENT);
    curl.setOpt(Curl.option.ACCEPT_ENCODING, 'gzip, deflate, br');
    curl.setOpt(Curl.option.CONNECTTIMEOUT_MS, 10000);
    curl.setOpt(Curl.option.TIMEOUT_MS, opts.timeoutMs || REQUEST_TIMEOUT_MS);
    curl.setOpt(Curl.option.HTTPHEADER, opts.headers || []);

    if (opts.method === 'POST') {
      curl.setOpt(Curl.option.POST, true);
      curl.setOpt(Curl.option.POSTFIELDS, opts.body || '');
    }

    curl.on('end', (statusCode, data) => {
      curl.close();
      resolve({ status: statusCode, body: data.toString() });
    });
    curl.on('error', (err) => {
      curl.close();
      reject(err);
    });
    curl.perform();
  });
}

function safeJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function errMsg(e) {
  return e instanceof Error ? e.message : String(e);
}

class StreamError extends Error {
  constructor(message, status = 502) {
    super(message);
    this.name = 'StreamError';
    this.status = status;
  }
}

/* ------------------------ helpers: encoding ------------------------ */
/* Python parity: quote(quote(title, safe=""), safe="") — encodeURIComponent
 * leaves !'()* unescaped while Python's quote() does not.               */

function pyQuote(s) {
  return encodeURIComponent(s).replace(
    /[!'()*]/g,
    (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase()
  );
}

function doubleEncodeTitle(title) {
  return pyQuote(pyQuote(String(title)));
}

/* --------------------------- TMDB metadata ------------------------- */

const metadataCache = new Map(); // "type:tmdbId" -> { meta, at }

function hasTmdb() {
  return Boolean(TMDB_API_KEY || TMDB_ACCESS_TOKEN);
}

async function tmdbGet(pathname, params = {}) {
  const qs = new URLSearchParams(params);
  if (TMDB_API_KEY) qs.set('api_key', TMDB_API_KEY);
  const headers = ['Accept: application/json'];
  if (TMDB_ACCESS_TOKEN) headers.push(`Authorization: Bearer ${TMDB_ACCESS_TOKEN}`);
  const res = await curlRequest(`${TMDB_API}${pathname}${qs.toString() ? `?${qs}` : ''}`, {
    headers,
  });
  const json = safeJson(res.body);
  if (res.status === 404) {
    throw new StreamError(`tmdb has no such ${pathname} (HTTP 404)`, 404);
  }
  if (!json || res.status !== 200) {
    throw new StreamError(
      `tmdb request failed for ${pathname}: HTTP ${res.status} ${String(res.body).slice(0, 120)}`
    );
  }
  return json;
}

async function fetchTmdbMeta(type, tmdbId) {
  const data = await tmdbGet(`/${type}/${tmdbId}`, {
    append_to_response: 'external_ids,translations',
  });
  const rawTitle =
    type === 'movie'
      ? data.title || data.original_title
      : data.name || data.original_name;
  const date = type === 'movie' ? data.release_date : data.first_air_date;
  const translations = Array.isArray(data.translations?.translations)
    ? data.translations.translations
    : [];
  const altTitles = {};
  for (const t of translations) {
    const alt = t.data ? t.data.title || t.data.name : null;
    if (t.iso_639_1 && alt) altTitles[t.iso_639_1] = alt;
  }
  return {
    tmdbId: String(tmdbId),
    imdbId: (data.external_ids && data.external_ids.imdb_id) || null,
    title: rawTitle || null,
    year: typeof date === 'string' && date.length >= 4 ? date.slice(0, 4) : null,
    posterPath: data.poster_path || null,
    backdropPath: data.backdrop_path || null,
    altTitles,
  };
}

/* Per-request overrides so the API also works without a TMDB key:
 *   ?title=&year=&imdbId=            (path id is a TMDB id)
 *   ?title=&year=&imdbId=&tmdbId=    (path id is an IMDb id)   */
function withOverrides(meta, q) {
  const out = { ...meta, altTitles: { ...(meta.altTitles || {}) } };
  const title = q.get('title');
  const year = q.get('year');
  const imdbId = q.get('imdbId') || q.get('imdb');
  const tmdbId = q.get('tmdbId') || q.get('tmdb');
  const poster = q.get('poster');
  const backdrop = q.get('backdrop');
  if (title) out.title = title;
  if (year && /^\d{4}/.test(year)) out.year = year.slice(0, 4);
  if (imdbId && /^tt\d+/i.test(imdbId)) out.imdbId = imdbId;
  if (tmdbId && /^\d+$/.test(tmdbId)) out.tmdbId = tmdbId;
  if (poster) out.posterPath = poster;
  if (backdrop) out.backdropPath = backdrop;
  return out;
}

async function resolveMetadata(type, id, q) {
  const ovTmdb = q.get('tmdbId') || q.get('tmdb');
  const ovImdb = q.get('imdbId') || q.get('imdb');
  const ovTitle = q.get('title');
  const ovYear = q.get('year');

  // keyless path: caller supplies everything
  const ov = withOverrides(
    { tmdbId: /^\d+$/.test(String(id)) ? id : null, imdbId: /^tt/i.test(id) ? id : null },
    q
  );
  if (ovTitle && ovYear && ov.imdbId && ov.tmdbId) {
    return ov;
  }

  let tmdbId = /^\d+$/.test(String(id)) ? String(id) : null;
  if (/^\d+$/.test(String(ovTmdb))) tmdbId = String(ovTmdb);

  if (!hasTmdb()) {
    throw new StreamError(
      'missing metadata — set TMDB_API_KEY or TMDB_ACCESS_TOKEN to resolve title/year/imdbId from the id, or pass ?title=&year=&imdbId= (&tmdbId= for IMDb path ids)',
      400
    );
  }
  if (!tmdbId) {
    const found = await tmdbGet(`/find/${encodeURIComponent(id)}`, {
      external_source: 'imdb_id',
    });
    const bucket = type === 'movie' ? found.movie_results : found.tv_results;
    const first = Array.isArray(bucket) ? bucket[0] : null;
    if (!first) {
      throw new StreamError(`no TMDB ${type} matches imdb id "${id}"`, 404);
    }
    tmdbId = String(first.id);
  }

  const cacheKey = `${type}:${tmdbId}`;
  const hit = metadataCache.get(cacheKey);
  if (hit && Date.now() - hit.at < METADATA_TTL_MS) {
    return withOverrides(hit.meta, q);
  }

  const meta = await fetchTmdbMeta(type, tmdbId);
  if (!meta.title || !meta.year || !meta.imdbId) {
    // wecollege needs all three; fail loudly rather than sending a broken url
    throw new StreamError(
      `tmdb metadata incomplete for ${type} ${tmdbId} (title/year/imdbId required)`,
      502
    );
  }
  metadataCache.set(cacheKey, { meta, at: Date.now() });
  return withOverrides(meta, q);
}

function tmdbImage(path) {
  if (!path) return null;
  if (/^https?:\/\//.test(path)) return path;
  return `https://image.tmdb.org/t/p/w500${path}`;
}

/* ------------------------- seed / media context -------------------- */

const mediaCache = new Map(); // mediaKey -> { type, season, episode, meta, seed, seedAt, decrypted: Map }
const inflight = new Map(); // key -> Promise (dedup concurrent identical fetches)

function mediaKey(type, tmdbId, season, episode) {
  return `${type}:${tmdbId}:${season || ''}:${episode || ''}`;
}

async function fetchSeed(tmdbId) {
  const res = await curlRequest(`${VIDY_BASE}/seed?mediaId=${encodeURIComponent(tmdbId)}`, {
    headers: ['Accept: application/json', ...VIDY_HEADERS],
  });
  const json = safeJson(res.body);
  if (res.status !== 200 || !json || !json.seed) {
    throw new StreamError(
      `seed fetch failed: HTTP ${res.status} ${String(res.body).replace(/\s+/g, ' ').slice(0, 140)}`
    );
  }
  return String(json.seed);
}

async function getMediaContext({ type, id, season, episode, q, force = false }) {
  const meta = await resolveMetadata(type, id, q);
  const key = mediaKey(type, meta.tmdbId, season, episode);

  const hit = mediaCache.get(key);
  if (!force && hit && Date.now() - hit.seedAt < SEED_CACHE_TTL_MS) {
    return { entry: hit, cached: true };
  }

  const pending = inflight.get(key);
  if (pending && !force) return { entry: await pending, cached: false };

  const task = (async () => {
    const seed = await fetchSeed(meta.tmdbId);
    const entry = { type, season, episode, meta, seed, seedAt: Date.now(), decrypted: new Map() };
    mediaCache.set(key, entry);
    return entry;
  })().finally(() => inflight.delete(key));

  inflight.set(key, task);
  return { entry: await task, cached: false };
}

/* --------------------------- sources fetch ------------------------- */

function pickTitle(entry, server) {
  const alt = server.altTitleLang && entry.meta.altTitles && entry.meta.altTitles[server.altTitleLang];
  return alt || entry.meta.title;
}

function buildSourcesUrl(entry, server) {
  const params = [
    `title=${doubleEncodeTitle(pickTitle(entry, server))}`,
    `mediaType=${entry.type}`,
    `year=${entry.meta.year || ''}`,
  ];
  if (entry.type === 'tv') {
    params.push(`episodeId=${entry.episode}`, `seasonId=${entry.season}`);
  }
  params.push(`tmdbId=${entry.meta.tmdbId}`);
  if (entry.meta.imdbId) params.push(`imdbId=${entry.meta.imdbId}`);
  if (server.language) params.push(`language=${server.language}`);
  params.push(`enc=${ENC_VERSION}`, `seed=${entry.seed}`);
  return `${VIDY_BASE}/${server.path}/sources?${params.join('&')}`;
}

async function decVideasy(text, tmdbId, seed) {
  const res = await curlRequest(`${ENCDEC_API}/dec-videasy`, {
    method: 'POST',
    headers: ['Content-Type: application/json', 'Accept: application/json'],
    body: JSON.stringify({ text, id: tmdbId, seed }),
  });
  const json = safeJson(res.body);
  if (!json || json.status !== 200 || json.result == null) {
    throw new Error(`dec-videasy failed: ${String(res.body).slice(0, 160)}`);
  }
  return json.result;
}

/* Normalize whatever shape dec-videasy returns into [{ url, quality, language }]. */
function extractSources(result) {
  let list = null;
  if (Array.isArray(result)) {
    list = result;
  } else if (result && typeof result === 'object') {
    for (const key of ['sources', 'streams', 'links', 'data']) {
      if (Array.isArray(result[key])) {
        list = result[key];
        break;
      }
    }
    if (!list && typeof result.url === 'string') list = [result];
  }
  if (!list) return [];
  const out = [];
  for (const s of list) {
    if (!s || typeof s !== 'object') continue;
    const url = s.url || s.link || s.file || s.source;
    if (typeof url !== 'string' || !/^https?:\/\//i.test(url)) continue;
    out.push({
      url,
      quality: s.quality || s.resolution || s.label || s.name || null,
      language: s.language || s.lang || null,
    });
  }
  return out;
}

function qualityRank(q) {
  if (!q) return -1;
  const s = String(q).toLowerCase();
  if (s.includes('2160') || s.includes('4k')) return 2160;
  if (s.includes('1440')) return 1440;
  const m = s.match(/(\d{3,4})/);
  return m ? Number(m[1]) : -1;
}

async function fetchSourcesForServer(entry, server) {
  const hit = entry.decrypted.get(server.path);
  if (hit && Date.now() - hit.at < STREAM_CACHE_TTL_MS) return hit.result;

  const t0 = performance.now();
  const res = await curlRequest(buildSourcesUrl(entry, server), {
    headers: [...VIDY_HEADERS],
  });
  if (res.status !== 200 || !res.body) {
    throw new Error(
      `sources HTTP ${res.status}${res.body ? `: ${String(res.body).replace(/\s+/g, ' ').slice(0, 100)}` : ' (empty body)'}`
    );
  }

  const result = await decVideasy(res.body, entry.meta.tmdbId, entry.seed);
  let sources = extractSources(result);
  if (server.filterQuality) {
    const filtered = sources.filter(
      (s) => String(s.quality || '').toLowerCase() === server.filterQuality.toLowerCase()
    );
    if (filtered.length > 0) sources = filtered;
  }
  if (sources.length === 0) {
    throw new Error('no playable sources in decrypted payload');
  }
  sources.sort((a, b) => qualityRank(b.quality) - qualityRank(a.quality));

  const out = { result, sources, best: sources[0], streamMs: Math.round(performance.now() - t0) };
  entry.decrypted.set(server.path, { result: out, at: Date.now() });
  return out;
}

/** Range-GET the playlist/segment to measure real CDN response time. */
async function probeStreamUrl(url) {
  const t0 = performance.now();
  try {
    const res = await curlRequest(url, {
      headers: [`Referer: ${VIDY_REFERER}`, 'Range: bytes=0-2047'],
      timeoutMs: PROBE_TIMEOUT_MS,
    });
    return { ok: res.status >= 200 && res.status < 400, ms: performance.now() - t0 };
  } catch {
    return { ok: false, ms: performance.now() - t0 };
  }
}

/* ------------------------------ helpers ---------------------------- */

function findServerIndex(param) {
  const trimmed = String(param).trim();

  if (/^\d+$/.test(trimmed)) {
    const n = Number.parseInt(trimmed, 10);
    if (n >= 1 && n <= SERVERS.length) return n - 1;
    throw new StreamError(
      `server ${n} is out of range — ${SERVERS.length} server(s) available: ${SERVERS.map(
        (s, i) => `${i + 1}=${s.name}`
      ).join(', ')}`,
      400
    );
  }

  const idx = SERVERS.findIndex((s) => s.name.toLowerCase() === trimmed.toLowerCase());
  if (idx === -1) {
    throw new StreamError(
      `unknown server "${trimmed}" — available: ${SERVERS.map(
        (s, i) => `${i + 1}=${s.name}`
      ).join(', ')}`,
      400
    );
  }
  return idx;
}

function applyWorkerPrefix(url, worker, encrypt = false) {
  if (!worker) return url;
  const base = encrypt ? WORKER_URL_EN.replace(/\/+$/, '') : WORKER_URL.replace(/\/+$/, '');
  return `${base}/${encrypt ? encryptUrlToken(url) : url}`;
}

/** Minimal concurrency limiter so 18 servers don't hammer the upstreams at once. */
async function pooled(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      results[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return results;
}

/* --------------------------- main resolver ------------------------- */

async function resolveStream(opts) {
  const t0 = performance.now();
  const { type, id, season, episode, serverParam, worker = false, encrypt = false, q } = opts;

  let { entry, cached } = await getMediaContext({ type, id, season, episode, q });

  const runOne = async (index) => {
    const server = SERVERS[index];
    const t1 = performance.now();
    try {
      const got = await fetchSourcesForServer(entry, server);
      const streamMs = got.streamMs || Math.round(performance.now() - t1);
      const probe = await probeStreamUrl(got.best.url);
      return {
        index: index + 1,
        name: server.name,
        description: server.description,
        ok: true,
        sourceCount: got.sources.length,
        quality: got.best.quality,
        streamMs,
        probeMs: Math.round(probe.ms),
        probeOk: probe.ok,
        totalMs: streamMs + (probe.ok ? Math.round(probe.ms) : 0),
        best: got.best,
        result: got.result,
        sources: got.sources,
      };
    } catch (e) {
      return {
        index: index + 1,
        name: server.name,
        description: server.description,
        ok: false,
        sourceCount: 0,
        quality: null,
        streamMs: Math.round(performance.now() - t1),
        probeMs: null,
        probeOk: false,
        totalMs: null,
        error: errMsg(e),
      };
    }
  };

  const successResponse = (winner, results, selectedBy) => ({
    success: true,
    type,
    id,
    ...(type === 'tv' ? { season, episode } : {}),
    title: entry.meta.title || (winner.result && winner.result.title) || null,
    poster: tmdbImage(entry.meta.posterPath),
    backdrop: tmdbImage(entry.meta.backdropPath),
    selectedBy,
    server: {
      index: winner.index,
      name: winner.name,
      description: winner.description,
      quality: winner.quality,
      streamMs: winner.streamMs,
      probeMs: winner.probeMs,
      totalMs: winner.totalMs,
    },
    originalUrl: winner.best.url,
    quality: winner.best.quality,
    url: applyWorkerPrefix(winner.best.url, worker || encrypt, encrypt),
    worker: worker || encrypt,
    encrypted: encrypt,
    playbackHeaders: {
      Referer: VIDY_REFERER,
      Origin: VIDY_ORIGIN,
      'User-Agent': USER_AGENT,
    },
    stream: winner.result,
    sources: winner.sources,
    ...(selectedBy === 'fastest'
      ? { servers: results.map(({ best, result, sources, ...rest }) => rest) }
      : {}),
    cached,
    elapsedMs: Math.round(performance.now() - t0),
    fetchedAt: new Date().toISOString(),
  });

  /* ---- explicit server requested ---- */
  if (serverParam) {
    const index = findServerIndex(serverParam);

    let r = await runOne(index);
    if (!r.ok && cached) {
      // stale seed/cache -> refresh once and retry
      const fresh = await getMediaContext({ type, id, season, episode, q, force: true });
      entry = fresh.entry;
      cached = false;
      r = await runOne(index);
    }
    if (!r.ok || !r.best) {
      throw new StreamError(
        `server "${serverParam}" (${r.name}) failed: ${r.error || 'unknown error'}`
      );
    }
    return successResponse(r, null, 'requested');
  }

  /* ---- race all servers, return the fastest ---- */
  let results = await pooled(SERVERS, FETCH_CONCURRENCY, (_, i) => runOne(i));

  if (!results.some((r) => r.ok) && cached) {
    const fresh = await getMediaContext({ type, id, season, episode, q, force: true });
    entry = fresh.entry;
    cached = false;
    results = await pooled(SERVERS, FETCH_CONCURRENCY, (_, i) => runOne(i));
  }

  const okResults = results.filter((r) => r.ok);
  if (okResults.length === 0) {
    throw new StreamError(
      `all ${results.length} servers failed: ${results
        .map((r) => `${r.name}: ${r.error}`)
        .join(' | ')}`
    );
  }

  // prefer servers whose playlist actually answered; rank by time-to-playlist
  const probeOk = okResults.filter((r) => r.probeOk);
  const pool = probeOk.length > 0 ? probeOk : okResults;
  pool.sort((a, b) => (a.totalMs || a.streamMs) - (b.totalMs || b.streamMs));
  const winner = pool[0];

  return successResponse(winner, results, 'fastest');
}

/* ---------------------------- http server -------------------------- */

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*',
  });
  res.end(body);
}

const ID_RE = /^[A-Za-z0-9_-]{2,64}$/;
const MOVIE_RE = /^\/api\/movie\/([^/]+)\/?$/;
const TV_RE = /^\/api\/tv\/([^/]+)\/(\d+)\/(\d+)\/?$/;
const TRUTHY = new Set(['1', 'true', 'yes', 'on']);

const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': '*',
    });
    return res.end();
  }
  if (req.method !== 'GET') {
    return sendJson(res, 405, { success: false, error: 'method not allowed' });
  }

  const u = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const sp = u.searchParams;
  const serverParam = sp.get('server');
  const worker = TRUTHY.has((sp.get('worker') || '').toLowerCase());
  const encrypt = (sp.get('data') || '').toLowerCase() === 'en';

  try {
    // index / health
    if (u.pathname === '/' || u.pathname === '') {
      return sendJson(res, 200, {
        success: true,
        service: 'stream-resolver-api',
        provider: `${VIDY_REFERER} (api.wecollege.net)`,
        decryptor: `${ENCDEC_API}/dec-videasy`,
        endpoints: [
          'GET /api/movie/{tmdbOrImdbId}[?server=1|name][&worker=1][&data=en][&title=&year=&imdbId=]',
          'GET /api/tv/{tmdbOrImdbId}/{season}/{episode}[?server=1|name][&worker=1][&data=en][&title=&year=&imdbId=]',
        ],
        tmdbConfigured: hasTmdb(),
        servers: SERVERS.map((s, i) => ({ index: i + 1, name: s.name, description: s.description })),
        worker: WORKER_URL,
        workerEn: WORKER_URL_EN,
      });
    }

    const movie = u.pathname.match(MOVIE_RE);
    if (movie) {
      const id = decodeURIComponent(movie[1]);
      if (!ID_RE.test(id)) {
        return sendJson(res, 400, {
          success: false,
          error: 'invalid id — expected a TMDB id (e.g. 27205) or an IMDb id (e.g. tt1375666)',
        });
      }
      return sendJson(
        res,
        200,
        await resolveStream({ type: 'movie', id, serverParam, worker, encrypt, q: sp })
      );
    }

    const tv = u.pathname.match(TV_RE);
    if (tv) {
      const id = decodeURIComponent(tv[1]);
      const season = Number.parseInt(tv[2], 10);
      const episode = Number.parseInt(tv[3], 10);
      if (!ID_RE.test(id) || season < 1 || episode < 1) {
        return sendJson(res, 400, {
          success: false,
          error: 'invalid params — expected /api/tv/{tmdbOrImdbId}/{season}/{episode}, e.g. /api/tv/1399/1/1',
        });
      }
      return sendJson(
        res,
        200,
        await resolveStream({ type: 'tv', id, season, episode, serverParam, worker, encrypt, q: sp })
      );
    }

    return sendJson(res, 404, { success: false, error: 'not found — see GET / for usage' });
  } catch (err) {
    const status = err instanceof StreamError ? err.status : 500;
    return sendJson(res, status, {
      success: false,
      error: err instanceof Error ? err.message : 'unknown error',
    });
  }
});

server.listen(PORT, () => {
  console.log(`stream-resolver-api (vidy.st) listening on http://0.0.0.0:${PORT}`);
});

process.on('unhandledRejection', (e) => console.error('unhandled rejection:', e));
process.on('uncaughtException', (e) => console.error('uncaught exception:', e));
