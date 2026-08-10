#!/usr/bin/env node
'use strict';
/*
 * Work Plan Management System — 后端鉴权服务（零依赖 Node）
 * -------------------------------------------------------------
 * 作用：把"账号 + 登录态"从浏览器 localStorage 移到服务端，
 *       使同一套前端在任意浏览器（Edge / Chrome / Firefox …）打开同一地址时，
 *       看到的都是同一份账号、都能正常登录，消除"账户不存在"。
 *
 * 提供：
 *   POST /api/bootstrap           一次性迁移：把浏览器本地 localStorage 账号 upsert 到服务端（仅放行一次）
 *   POST /api/login               校验账号密码，返回 { token, user }
 *   GET  /api/me                  返回当前登录用户（需 Bearer token）
 *   GET  /api/users               返回账号（管理员=全部；普通用户=仅自己）
 *   POST /api/users               新建单个账号（管理员；已存在则 409）—— 创建即实时上传
 *   PUT  /api/users               批量合并 upsert（管理员逐条 upsert 且保留他人；普通用户仅改自身）
 *   PUT  /api/users/:username     更新单条账号（管理员任意；本人仅基础字段）
 *   DELETE /api/users/:username   删除单条账号（管理员；admin 自身不可删）
 *   /                             静态托管前端 index.html（自动注入 window.__USE_API 标志）
 *
 * 密码：与前端完全一致 —— passHash = 'v1$' + SHA-256(utf8(salt + ':' + password))，服务端只存哈希，不存明文
 * 数据：server/data/db.json（首次运行自动种子 admin / Rainbow@2026；首次迁移后写入 bootstrapDone 标记）
 *
 * 运行：node server.js   （端口可用 PORT 环境变量覆盖，默认 3000）
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = __dirname;
// 前端 index.html 位置：按候选顺序探测，兼容不同部署目录结构（可用 PUBLIC_DIR 覆盖）
const PUBLIC_CANDIDATES = [
  process.env.PUBLIC_DIR,
  path.resolve(ROOT, '..', 'deploy', 'index.html'),
  path.resolve(ROOT, 'deploy', 'index.html'),
  path.resolve(ROOT, 'public', 'index.html'),
  path.resolve(process.cwd(), 'deploy', 'index.html'),
  path.resolve(process.cwd(), 'index.html')
].filter(Boolean);
function resolvePublicHtml() {
  for (var i = 0; i < PUBLIC_CANDIDATES.length; i++) {
    try { if (fs.existsSync(PUBLIC_CANDIDATES[i])) return PUBLIC_CANDIDATES[i]; } catch (e) {}
  }
  return PUBLIC_CANDIDATES[PUBLIC_CANDIDATES.length - 1];
}
const PUBLIC_HTML = resolvePublicHtml();
const DATA_DIR = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.resolve(ROOT, 'data');
const DB_FILE = process.env.DB_FILE || path.join(DATA_DIR, 'db.json');
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const SECRET = (function () {
  // 持久化的服务签名密钥；首次生成后写入 db.json，重启不变
  return null;
})();

// ---------- 密码哈希（与前端一致）----------
function sha256hex(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}
function hashPass(pw, salt) {
  return 'v1$' + sha256hex(salt + ':' + pw);
}
function verifyPass(pw, salt, passHash) {
  if (!salt || !passHash) return false;
  return hashPass(pw, salt) === passHash;
}

// ---------- token（HMAC-SHA256 签名）----------
function loadDB() {
  try {
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch (e) {
    return null;
  }
}
function saveDB(db) {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf8');
}
function getSecret(db) {
  if (!db.secret) {
    db.secret = crypto.randomBytes(32).toString('hex');
    saveDB(db);
  }
  return db.secret;
}
function makeToken(db, username) {
  const sec = getSecret(db);
  const payload = Buffer.from(JSON.stringify({ username: username, exp: Date.now() + 1000 * 60 * 60 * 24 * 7 })).toString('base64url');
  const sig = crypto.createHmac('sha256', sec).update(payload).digest('base64url');
  return payload + '.' + sig;
}
function verifyToken(db, token) {
  if (!token || typeof token !== 'string' || token.indexOf('.') < 0) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const sec = getSecret(db);
  const expect = crypto.createHmac('sha256', sec).update(parts[0]).digest('base64url');
  // 防时序攻击的等长比较
  if (expect.length !== parts[1].length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(expect), Buffer.from(parts[1]))) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    if (!payload.exp || payload.exp < Date.now()) return null;
    return payload.username;
  } catch (e) {
    return null;
  }
}

// ---------- 账号公开字段（去掉 salt / passHash，并暴露 hasPassword 供前端判断）----------
function publicUser(u) {
  if (!u) return null;
  const c = Object.assign({}, u);
  delete c.salt;
  delete c.passHash;
  c.hasPassword = !!u.passHash; // 仅告知"是否已设密码"，不泄露哈希
  return c;
}

// ---------- 统一清洗/规范化一条账号记录（服务端权威格式）----------
// asAdmin=true 时允许写入 isAdmin / mgrAccess 等权限字段；普通用户仅能改自身基础字段。
function sanitizeUser(x, asAdmin) {
  if (!x) return null;
  const un = String(x.username || '').trim();
  if (!un) return null;
  const isAdmin = asAdmin && !!x.isAdmin;
  const rec = {
    username: un,
    name: x.name || '',
    salt: x.salt || '', passHash: x.passHash || '',
    dept: x.dept || '', region: x.region || '',
    mgrAccess: !!(isAdmin || x.mgrAccess),
    canAccessMgr: !!(isAdmin || x.mgrAccess),
    allowedDepts: Array.isArray(x.allowedDepts) ? x.allowedDepts : [],
    allowedRegions: Array.isArray(x.allowedRegions) ? x.allowedRegions : [],
    isAdmin: isAdmin,
    mustChange: !!x.mustChange
  };
  if (rec.username === 'admin') { rec.isAdmin = true; rec.mgrAccess = true; rec.canAccessMgr = true; }
  return rec;
}

// ---------- 种子 ----------
function ensureSeed(db) {
  if (db.users && db.users.length) return;
  const salt = crypto.randomBytes(8).toString('hex');
  db.users = [{
    username: 'admin', name: 'Administrador', salt: salt, passHash: hashPass('Rainbow@2026', salt),
    dept: 'Management', region: 'All', mgrAccess: true, canAccessMgr: true,
    allowedDepts: ['All'], allowedRegions: ['All'], isAdmin: true, mustChange: true
  }];
  saveDB(db);
}

// ---------- 首次初始化 ----------
let DB = loadDB() || { users: [] };
ensureSeed(DB);
if (!DB.secret) { DB.secret = crypto.randomBytes(32).toString('hex'); saveDB(DB); }

// ---------- HTTP 工具 ----------
function sendJSON(res, code, obj) {
  return new Promise(function (resolve) {
    const body = JSON.stringify(obj);
    res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(body);
    resolve();
  });
}
function readBody(req) {
  return new Promise(function (resolve, reject) {
    let data = '';
    req.on('data', function (c) { data += c; if (data.length > 1e6) req.destroy(); });
    req.on('end', function () { try { resolve(data ? JSON.parse(data) : {}); } catch (e) { reject(new Error('JSON inválido')); } });
    req.on('error', reject);
  });
}
function authUser(req) {
  const h = req.headers['authorization'] || '';
  const m = /^Bearer\s+(.+)$/.exec(h);
  if (!m) return null;
  const username = verifyToken(DB, m[1]);
  if (!username) return null;
  return DB.users.filter(function (u) { return u.username === username; })[0] || null;
}

// ---------- 路由 ----------
function handleApi(req, res, url) {
  const p = url.pathname;
  const method = req.method.toUpperCase();

  if (p === '/api/login' && method === 'POST') {
    return readBody(req).then(function (b) {
      const u = (DB.users || []).filter(function (x) { return x.username === b.username; })[0];
      if (!u || !verifyPass(b.password || '', u.salt, u.passHash)) {
        return sendJSON(res, 401, { error: 'Usuário ou senha incorretos' });
      }
      return sendJSON(res, 200, { token: makeToken(DB, u.username), user: publicUser(u) });
    }).catch(function (e) { return sendJSON(res, 400, { error: e.message }); });
  }

  if (p === '/api/me' && method === 'GET') {
    const u = authUser(req);
    if (!u) return sendJSON(res, 401, { error: 'Não autenticado' });
    return sendJSON(res, 200, { user: publicUser(u) });
  }

  // ===================== 一次性迁移：本地浏览器账号 -> 服务端 =====================
  // 无需登录即可调用，且仅在"服务端仅有种子 admin、且尚未迁移过"时放行一次。
  // 传输的是已哈希的 {salt,passHash}，绝不发送明文密码；迁移完成后 db.bootstrapDone=true 永久关闭。
  if (p === '/api/bootstrap' && method === 'POST') {
    if (DB.bootstrapDone) return sendJSON(res, 409, { error: 'Migração já realizada' });
    if (DB.users.length > 1) return sendJSON(res, 409, { error: 'Já existem usuários no servidor' });
    return readBody(req).then(function (b) {
      const incoming = b.users || [];
      if (!Array.isArray(incoming)) return sendJSON(res, 400, { error: 'Formato inválido' });
      incoming.forEach(function (x) {
        const rec = sanitizeUser(x, true);
        if (!rec || !rec.username) return;
        const idx = DB.users.findIndex(function (y) { return y.username === rec.username; });
        if (idx < 0) DB.users.push(rec); else DB.users[idx] = rec; // upsert（同用户名以本地为准）
      });
      DB.bootstrapDone = true;
      saveDB(DB);
      return sendJSON(res, 200, { users: DB.users.map(publicUser), migrated: incoming.length });
    }).catch(function (e) { return sendJSON(res, 400, { error: e.message }); });
  }

  // ===================== 账号读写 =====================
  if (p === '/api/users' && method === 'GET') {
    const u = authUser(req);
    if (!u) return sendJSON(res, 401, { error: 'Não autenticado' });
    // 管理员看全部；普通用户只看自己
    const list = u.isAdmin ? DB.users : DB.users.filter(function (x) { return x.username === u.username; });
    return sendJSON(res, 200, { users: list.map(publicUser) });
  }

  if (p === '/api/users' && method === 'POST') {
    // 新建单个用户（管理员）。409 若已存在。语义等于"创建即实时上传"。
    const u = authUser(req);
    if (!u) return sendJSON(res, 401, { error: 'Não autenticado' });
    if (!u.isAdmin) return sendJSON(res, 403, { error: 'Apenas administrador' });
    return readBody(req).then(function (b) {
      if (!b || !b.username) return sendJSON(res, 400, { error: 'username obrigatório' });
      const un = String(b.username).trim();
      if (!un) return sendJSON(res, 400, { error: 'username inválido' });
      if (DB.users.some(function (x) { return x.username === un; }))
        return sendJSON(res, 409, { error: 'Usuário já existe' });
      const rec = sanitizeUser(b, true);
      if (!rec || !rec.username) return sendJSON(res, 400, { error: 'username inválido' });
      DB.users.push(rec);
      saveDB(DB);
      return sendJSON(res, 201, { users: DB.users.map(publicUser), user: publicUser(rec) });
    }).catch(function (e) { return sendJSON(res, 400, { error: e.message }); });
  }

  if (p === '/api/users' && method === 'PUT') {
    // 批量合并（upsert）：管理员=逐条 upsert 并保留库中存在但 payload 未列的账号；
    // 普通用户=仅可 upsert 自身(salt/passHash/name/mustChange)。
    // 供前端 saveUsers() 调用 —— 任意一次编辑（含新建/改密）都会实时上传，且不会因整表覆盖丢失他人数据。
    const u = authUser(req);
    if (!u) return sendJSON(res, 401, { error: 'Não autenticado' });
    return readBody(req).then(function (b) {
      const incoming = b.users || [];
      if (!Array.isArray(incoming)) return sendJSON(res, 400, { error: 'Formato inválido' });
      if (u.isAdmin) {
        const byName = {};
        DB.users.forEach(function (x) { byName[x.username] = x; }); // 先载入库中所有账号（含未列出的）
        incoming.forEach(function (x) {
          const rec = sanitizeUser(x, true);
          if (!rec || !rec.username) return;
          byName[rec.username] = rec; // upsert，绝不删除他人
        });
        DB.users = Object.keys(byName).map(function (k) { return byName[k]; });
      } else {
        const me = incoming.filter(function (x) { return x.username === u.username; })[0];
        if (!me) return sendJSON(res, 400, { error: 'Só é permitido alterar o próprio usuário' });
        const rec = sanitizeUser({ username: u.username, name: me.name, salt: me.salt, passHash: me.passHash, mustChange: me.mustChange }, false);
        const idx = DB.users.findIndex(function (x) { return x.username === u.username; });
        if (idx < 0) DB.users.push(rec); else DB.users[idx] = rec;
      }
      saveDB(DB);
      return sendJSON(res, 200, { users: DB.users.map(publicUser) });
    }).catch(function (e) { return sendJSON(res, 400, { error: e.message }); });
  }

  // 单条：PUT /api/users/:username（更新） | DELETE /api/users/:username（删除）
  const mU = /^\/api\/users\/(.+)$/.exec(p);
  if (mU) {
    const un = decodeURIComponent(mU[1]);
    if (method === 'PUT') {
      const u = authUser(req);
      if (!u) return sendJSON(res, 401, { error: 'Não autenticado' });
      if (!u.isAdmin && u.username !== un) return sendJSON(res, 403, { error: 'Apenas administrador ou o próprio usuário' });
      return readBody(req).then(function (b) {
        const rec = sanitizeUser(Object.assign({}, b, { username: un }), u.isAdmin);
        const idx = DB.users.findIndex(function (x) { return x.username === un; });
        if (idx < 0) DB.users.push(rec); else DB.users[idx] = rec;
        saveDB(DB);
        return sendJSON(res, 200, { users: DB.users.map(publicUser), user: publicUser(rec) });
      }).catch(function (e) { return sendJSON(res, 400, { error: e.message }); });
    }
    if (method === 'DELETE') {
      const u = authUser(req);
      if (!u) return sendJSON(res, 401, { error: 'Não autenticado' });
      if (!u.isAdmin) return sendJSON(res, 403, { error: 'Apenas administrador' });
      if (un === 'admin') return sendJSON(res, 403, { error: 'Não é possível excluir o administrador' });
      const before = DB.users.length;
      DB.users = DB.users.filter(function (x) { return x.username !== un; });
      if (DB.users.length === before) return sendJSON(res, 404, { error: 'Usuário não encontrado' });
      saveDB(DB);
      return sendJSON(res, 200, { users: DB.users.map(publicUser) });
    }
    return sendJSON(res, 405, { error: 'Método não permitido' });
  }

  return sendJSON(res, 404, { error: 'Não encontrado' });
}

// ---------- 静态托管（注入 API 标志）----------
const INJECT = '<script>window.__USE_API=true;window.__API_BASE="";</script>';
function serveIndex(res) {
  const htmlPath = (PUBLIC_HTML && fs.existsSync(PUBLIC_HTML)) ? PUBLIC_HTML : resolvePublicHtml();
  let html;
  try { html = fs.readFileSync(htmlPath, 'utf8'); } catch (e) {
    res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('index.html não encontrado (verifique PUBLIC_DIR). Candidato: ' + htmlPath);
    return;
  }
  if (html.indexOf('__USE_API=true') < 0) {
    html = html.replace(/<\/head>/i, INJECT + '</head>');
  }
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}

const server = http.createServer(function (req, res) {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname.indexOf('/api/') === 0) {
    handleApi(req, res, url).catch(function (e) { sendJSON(res, 500, { error: e.message }); });
    return;
  }
  if (url.pathname === '/' || url.pathname === '/index.html') {
    serveIndex(res);
    return;
  }
  // 其它静态资源（如有）回退到 deploy 目录
  const cand = path.resolve(path.join(ROOT, '..', 'deploy'), '.' + url.pathname);
  if (cand.indexOf(path.resolve(ROOT, '..', 'deploy')) === 0 && fs.existsSync(cand) && fs.statSync(cand).isFile()) {
    const ext = path.extname(cand).toLowerCase();
    const ct = { '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.svg': 'image/svg+xml', '.json': 'application/json' }[ext] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': ct });
    res.end(fs.readFileSync(cand));
    return;
  }
  serveIndex(res); // SPA 兜底
});

server.listen(PORT, HOST, function () {
  console.log('Work Plan backend ouvindo em http://' + HOST + ':' + PORT + '  (HOST=' + HOST + ')');
  console.log('Contas serve-side em: ' + DB_FILE);
  console.log('Seed admin: Rainbow@2026  (altere no primeiro acesso)');
});
