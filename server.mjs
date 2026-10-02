/**
 * server.mjs — 零依赖 Node 静态服务
 *   GET /            -> public/index.html
 *   GET /healthz     -> 200 {"status":"ok"}
 *   GET /<asset>     -> public/<asset>（防路径逃逸）
 *
 * 宿主端口由环境变量 PORT 配置（compose 映射时使用）。
 */
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = resolve(__dirname, 'public');
const PORT = Number(process.env.PORT) || 8080;
const HOST = process.env.HOST || '0.0.0.0';

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

function sendJson(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
  });
  res.end(body);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'local'}`);
  const pathname = decodeURIComponent(url.pathname);

  if (pathname === '/healthz' || pathname === '/health') {
    return sendJson(res, 200, {
      status: 'ok',
      service: 'avionics-link-review',
      time: new Date().toISOString(),
    });
  }
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    return sendJson(res, 405, { error: 'method not allowed' });
  }

  let rel = pathname === '/' ? '/index.html' : pathname;
  const safe = normalize(rel).replace(/^([/\\])+/, '');
  const filePath = join(PUBLIC_DIR, safe);
  if (!filePath.startsWith(PUBLIC_DIR + '/') && filePath !== PUBLIC_DIR) {
    return sendJson(res, 403, { error: 'forbidden' });
  }
  try {
    const data = await readFile(filePath);
    res.writeHead(200, {
      'content-type': MIME[extname(filePath)] || 'application/octet-stream',
      'content-length': data.length,
      'cache-control': 'no-store',
    });
    res.end(req.method === 'HEAD' ? undefined : data);
  } catch (e) {
    if (e.code === 'ENOENT') return sendJson(res, 404, { error: 'not found' });
    sendJson(res, 500, { error: 'internal error' });
  }
});

server.listen(PORT, HOST, () => {
  const actual = server.address().port;
  console.log(`[avionics-link-review] listening on http://${HOST}:${actual}`);
});

const shutdown = () => server.close(() => process.exit(0));
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
