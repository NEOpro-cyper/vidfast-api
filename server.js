#!/usr/bin/env node
/**
 * VidFast Stream Resolver API — standalone single-file server.
 * No framework. Only dependency: node-libcurl (plain Node fetch gets 403'd
 * by vidfast.vc's Cloudflare TLS fingerprinting; libcurl passes).
 *
 * Endpoints:
 *   GET /api/movie/{tmdbOrImdbId}                          ?server=1|name  &worker=1
 *   GET /api/tv/{tmdbOrImdbId}/{season}/{episode}          ?server=1|name  &worker=1
 *   GET /                                                  -> info
 *
 * Run:   npm install && node server.js     (PORT env overrides default 3000)
 */

'use strict';

const http = require('node:http');
const { Curl } = require('node-libcurl');

/* ----------------------------- config ----------------------------- */

const PORT = Number(process.env.PORT) || 3000;
const VIDFAST_BASE = 'https://vidfast.vc';
const ENCDEC_API = 'https://enc-dec.app/api';
const WORKER_URL =
  process.env.WORKER_URL || 'https://icy-art-1d5b-movy.ntb7nmytsd.workers.dev/';

// Worker used ONLY for ?data=en (encrypted mode)
const WORKER_URL_EN =
  process.env.WORKER_URL_EN || 'https://solitary-mov-8449-yen.ntb7nmytsd.workers.dev/';

/* ------------------------ URL encryptor (?data=en) ------------------------ */
// When a request includes ?data=en, the stream url is rewritten as
// `${WORKER_URL_EN}/${encryptedToken}` instead of plain text.
// Token format (must match the SECRET in your decrypt worker):
//   v1.<b64url(iv)>.<b64url(ciphertext+authtag)>
const crypto = require('node:crypto');
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

const VIDFAST_HEADERS = [
  'Referer: https://vidfast.vc/',
  'Origin: https://vidfast.vc',
  'X-Requested-With: XMLHttpRequest',
];

const SERVERS_CACHE_TTL_MS = 15 * 60 * 1000; // server list fresh for 15 min
const STREAM_CACHE_TTL_MS = 8 * 60 * 1000;   // decrypted stream fresh for 8 min
const REQUEST_TIMEOUT_MS = 20000;
const PROBE_TIMEOUT_MS = 6000;

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

/* --------------------------- token extraction ---------------------- */
/* TV pages embed the payload under \"token\":\", movie pages under \"en\":\" */

function extractPageToken(html) {
  const tokenMatch = html.match(/\\"token\\":\\"(.*?)\\"/);
  if (tokenMatch && tokenMatch[1]) return tokenMatch[1];

  const enMatch = html.match(/\\"en\\":\\"([^"\\]{20,})\\"/);
  if (enMatch && enMatch[1]) return enMatch[1];

  const all = [...html.matchAll(/\\"(?:en|token)\\":\\"(.*?)\\"/g)]
    .map((m) => m[1])
    .sort((a, b) => b.length - a.length);
  return all[0] || null;
}

/* ---------------------------- enc-dec.app -------------------------- */

async function encDecGet(stage, text) {
  const res = await curlRequest(
    `${ENCDEC_API}/enc-vidfast?text=${encodeURIComponent(text)}&stage=${stage}`
  );
  const json = safeJson(res.body);
  if (!json || json.status !== 200 || !json.result) {
    throw new VidfastError(`enc-dec stage ${stage} failed: ${res.body.slice(0, 160)}`);
  }
  return json.result;
}

async function decVidfast(text) {
  const res = await curlRequest(`${ENCDEC_API}/dec-vidfast`, {
    method: 'POST',
    headers: ['Content-Type: application/json'],
    body: JSON.stringify({ text }),
  });
  const json = safeJson(res.body);
  if (!json || json.status !== 200) {
    throw new VidfastError(`dec-vidfast failed: ${res.body.slice(0, 160)}`);
  }
  return json.result;
}

/* ------------------------- servers list cache ---------------------- */

const serversCache = new Map(); // key -> { servers, streamBase, csrfToken, fetchedAt, streams }
const inflight = new Map(); // key -> Promise (dedup concurrent identical fetches)

function mediaKey(type, id, season, episode) {
  return `${type}:${id}:${season || ''}:${episode || ''}`;
}

function pageUrl(type, id, season, episode) {
  return type === 'movie'
    ? `${VIDFAST_BASE}/movie/${id}/`
    : `${VIDFAST_BASE}/tv/${id}/${season}/${episode}/`;
}

async function fetchServersEntry(type, id, season, episode) {
  // 1. vidfast page -> embedded token
  const page = await curlRequest(pageUrl(type, id, season, episode), {
    headers: ['Accept: text/html,application/xhtml+xml'],
  });
  if (page.status !== 200) {
    throw new VidfastError(
      `vidfast page returned HTTP ${page.status} (possibly blocked by Cloudflare)`
    );
  }
  const token = extractPageToken(page.body);
  if (!token) throw new VidfastError('could not extract token from the vidfast page');

  // 2. stage 1 -> upload url + csrf
  const s1 = await encDecGet(1, token);
  if (!s1.stage1 || !s1.token) {
    throw new VidfastError('enc-dec stage 1 returned an unexpected payload');
  }

  // 3. POST stage 1
  const post1 = await curlRequest(s1.stage1, {
    method: 'POST',
    headers: [...VIDFAST_HEADERS, `X-CSRF-Token: ${s1.token}`],
  });
  if (!post1.body) {
    throw new VidfastError(`stage 1 POST returned an empty body (HTTP ${post1.status})`);
  }

  // 4. stage 2 -> servers url, stream url base, new csrf
  const s2 = await encDecGet(2, post1.body);
  if (!s2.servers || !s2.stream || !s2.token) {
    throw new VidfastError('enc-dec stage 2 returned an unexpected payload');
  }

  // 5. POST servers -> encrypted list
  const postServers = await curlRequest(s2.servers, {
    method: 'POST',
    headers: [...VIDFAST_HEADERS, `X-CSRF-Token: ${s2.token}`],
  });
  if (!postServers.body) {
    throw new VidfastError(`servers POST returned an empty body (HTTP ${postServers.status})`);
  }

  // 6. decrypt
  const servers = await decVidfast(postServers.body);
  if (!Array.isArray(servers) || servers.length === 0) {
    throw new VidfastError('no servers are available for this media', 404);
  }

  return {
    servers,
    streamBase: s2.stream,
    csrfToken: s2.token,
    fetchedAt: Date.now(),
    streams: new Map(), // server.data -> { result, at }
  };
}

async function getServersEntry(type, id, season, episode, force = false) {
  const key = mediaKey(type, id, season, episode);

  const hit = serversCache.get(key);
  if (!force && hit && Date.now() - hit.fetchedAt < SERVERS_CACHE_TTL_MS) {
    return { entry: hit, cached: true };
  }

  const pending = inflight.get(key);
  if (pending) return { entry: await pending, cached: false };

  const task = (async () => {
    const entry = await fetchServersEntry(type, id, season, episode);
    serversCache.set(key, entry);
    return entry;
  })().finally(() => inflight.delete(key));

  inflight.set(key, task);
  return { entry: await task, cached: false };
}

/* --------------------------- stream fetching ----------------------- */

async function fetchStreamForServer(entry, server) {
  const hit = entry.streams.get(server.data);
  if (hit && Date.now() - hit.at < STREAM_CACHE_TTL_MS) return hit.result;

  const res = await curlRequest(`${entry.streamBase}/${server.data}`, {
    method: 'POST',
    headers: [...VIDFAST_HEADERS, `X-CSRF-Token: ${entry.csrfToken}`],
  });
  if (!res.body) {
    throw new Error(`stream POST returned an empty body (HTTP ${res.status})`);
  }

  const stream = await decVidfast(res.body);
  if (!stream || typeof stream.url !== 'string' || !stream.url) {
    throw new Error('stream decryption returned no playable url');
  }

  entry.streams.set(server.data, { result: stream, at: Date.now() });
  return stream;
}

/** Range-GET the m3u8 to measure real CDN response time. */
async function probeStreamUrl(url) {
  const t0 = performance.now();
  try {
    const res = await curlRequest(url, {
      headers: ['Referer: https://vidfast.vc/', 'Range: bytes=0-2047'],
      timeoutMs: PROBE_TIMEOUT_MS,
    });
    return { ok: res.status >= 200 && res.status < 400, ms: performance.now() - t0 };
  } catch {
    return { ok: false, ms: performance.now() - t0 };
  }
}

/* ------------------------------ helpers ---------------------------- */

class VidfastError extends Error {
  constructor(message, status = 502) {
    super(message);
    this.name = 'VidfastError';
    this.status = status;
  }
}

function findServerIndex(servers, param) {
  const trimmed = String(param).trim();

  if (/^\d+$/.test(trimmed)) {
    const n = Number.parseInt(trimmed, 10);
    if (n >= 1 && n <= servers.length) return n - 1;
    throw new VidfastError(
      `server ${n} is out of range — ${servers.length} server(s) available: ${servers
        .map((s, i) => `${i + 1}=${s.name}`)
        .join(', ')}`,
      400
    );
  }

  const idx = servers.findIndex((s) => s.name.toLowerCase() === trimmed.toLowerCase());
  if (idx === -1) {
    throw new VidfastError(
      `unknown server "${trimmed}" — available: ${servers
        .map((s, i) => `${i + 1}=${s.name}`)
        .join(', ')}`,
      400
    );
  }
  return idx;
}

function applyWorkerPrefix(url, worker, encrypt = false) {
  if (!worker) return url;
  const base = encrypt
    ? WORKER_URL_EN.replace(/\/+$/, '')
    : WORKER_URL.replace(/\/+$/, '');
  return `${base}/${encrypt ? encryptUrlToken(url) : url}`;
}

function tmdbImage(path) {
  if (!path) return null;
  if (/^https?:\/\//.test(path)) return path;
  return `https://image.tmdb.org/t/p/w500${path}`;
}

/* --------------------------- main resolver ------------------------- */

async function resolveStream(opts) {
  const t0 = performance.now();
  const { type, id, season, episode, serverParam, worker = false, encrypt = false } = opts;

  let { entry, cached } = await getServersEntry(type, id, season, episode);

  const runOne = async (index) => {
    const server = entry.servers[index];
    const t1 = performance.now();
    try {
      const stream = await fetchStreamForServer(entry, server);
      const streamMs = Math.round(performance.now() - t1);
      const probe = await probeStreamUrl(stream.url);
      return {
        index: index + 1,
        name: server.name,
        description: server.description,
        ok: true,
        streamMs,
        probeMs: Math.round(probe.ms),
        probeOk: probe.ok,
        totalMs: streamMs + (probe.ok ? Math.round(probe.ms) : 0),
        url: stream.url,
        stream,
      };
    } catch (e) {
      return {
        index: index + 1,
        name: server.name,
        description: server.description,
        ok: false,
        streamMs: Math.round(performance.now() - t1),
        probeMs: null,
        probeOk: false,
        totalMs: null,
        error: e instanceof Error ? e.message : String(e),
      };
    }
  };

  /* ---- explicit server requested ---- */
  if (serverParam) {
    const index = findServerIndex(entry.servers, serverParam);

    let r = await runOne(index);
    if (!r.ok && cached) {
      // stale cache -> refresh once and retry
      const fresh = await getServersEntry(type, id, season, episode, true);
      entry = fresh.entry;
      cached = false;
      r = await runOne(index);
    }
    if (!r.ok || !r.stream) {
      throw new VidfastError(
        `server "${serverParam}" (${r.name}) failed: ${r.error || 'unknown error'}`
      );
    }

    return {
      success: true,
      type,
      id,
      ...(type === 'tv' ? { season, episode } : {}),
      title: r.stream.title || null,
      poster: tmdbImage(r.stream.poster),
      backdrop: tmdbImage(r.stream.backdrop),
      selectedBy: 'requested',
      server: {
        index: r.index,
        name: r.name,
        description: r.description,
        streamMs: r.streamMs,
        probeMs: r.probeMs,
        totalMs: r.totalMs,
      },
      originalUrl: r.stream.url,
      url: applyWorkerPrefix(r.stream.url, worker || encrypt, encrypt),
      worker: worker || encrypt,
      encrypted: encrypt,
      stream: r.stream,
      cached,
      elapsedMs: Math.round(performance.now() - t0),
      fetchedAt: new Date().toISOString(),
    };
  }

  /* ---- race all servers, return the fastest ---- */
  let results = await Promise.all(entry.servers.map((_, i) => runOne(i)));

  if (!results.some((r) => r.ok) && cached) {
    const fresh = await getServersEntry(type, id, season, episode, true);
    entry = fresh.entry;
    cached = false;
    results = await Promise.all(entry.servers.map((_, i) => runOne(i)));
  }

  const okResults = results.filter((r) => r.ok);
  if (okResults.length === 0) {
    throw new VidfastError(
      `all ${results.length} servers failed: ${results
        .map((r) => `${r.name}: ${r.error}`)
        .join(' | ')}`
    );
  }

  // prefer servers whose m3u8 actually answered; rank by time-to-playlist
  const probeOk = okResults.filter((r) => r.probeOk);
  const pool = probeOk.length > 0 ? probeOk : okResults;
  pool.sort((a, b) => (a.totalMs || a.streamMs) - (b.totalMs || b.streamMs));
  const winner = pool[0];

  return {
    success: true,
    type,
    id,
    ...(type === 'tv' ? { season, episode } : {}),
    title: winner.stream.title || null,
    poster: tmdbImage(winner.stream.poster),
    backdrop: tmdbImage(winner.stream.backdrop),
    selectedBy: 'fastest',
    server: {
      index: winner.index,
      name: winner.name,
      description: winner.description,
      streamMs: winner.streamMs,
      probeMs: winner.probeMs,
      totalMs: winner.totalMs,
    },
    originalUrl: winner.stream.url,
    url: applyWorkerPrefix(winner.stream.url, worker || encrypt, encrypt),
    worker: worker || encrypt,
    encrypted: encrypt,
    stream: winner.stream,
    servers: results.map(({ stream, ...rest }) => rest),
    cached,
    elapsedMs: Math.round(performance.now() - t0),
    fetchedAt: new Date().toISOString(),
  };
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
        service: 'vidfast-stream-api',
        endpoints: [
          'GET /api/movie/{tmdbOrImdbId}[?server=1|name][&worker=1][&data=en]',
          'GET /api/tv/{tmdbOrImdbId}/{season}/{episode}[?server=1|name][&worker=1][&data=en]',
        ],
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
          error: 'invalid id — expected a TMDB id (e.g. 27205) or an IMDb id (e.g. tt15398776)',
        });
      }
      return sendJson(res, 200, await resolveStream({ type: 'movie', id, serverParam, worker, encrypt }));
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
      return sendJson(res, 200, await resolveStream({ type: 'tv', id, season, episode, serverParam, worker, encrypt }));
    }

    return sendJson(res, 404, { success: false, error: 'not found — see GET / for usage' });
  } catch (err) {
    const status = err instanceof VidfastError ? err.status : 500;
    return sendJson(res, status, {
      success: false,
      error: err instanceof Error ? err.message : 'unknown error',
    });
  }
});

server.listen(PORT, () => {
  console.log(`vidfast-stream-api listening on http://0.0.0.0:${PORT}`);
});

process.on('unhandledRejection', (e) => console.error('unhandled rejection:', e));
process.on('uncaughtException', (e) => console.error('uncaught exception:', e));
