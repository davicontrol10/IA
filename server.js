import express from 'express';
import pkg from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const { Pool } = pkg;
const __dirname = dirname(fileURLToPath(import.meta.url));

/* ---------- configuração por variáveis de ambiente ---------- */
const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;          // string de conexão do Postgres do EasyPanel
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;      // sua chave — fica só aqui no servidor
const JWT_SECRET = process.env.JWT_SECRET || 'troque-este-segredo';
const REGISTER_CODE = process.env.REGISTER_CODE || '';  // se preenchido, exige código pra criar conta

// e-mail (2FA). Se não configurar, o código sai nos logs do servidor (modo teste).
const SMTP_HOST = process.env.SMTP_HOST || '';
const SMTP_PORT = +process.env.SMTP_PORT || 587;
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || '';
const MAIL_FROM = process.env.MAIL_FROM || SMTP_USER;

// N8N (automações). Endereço e chave do SEU n8n — ficam só no servidor.
const N8N_URL = (process.env.N8N_URL || '').replace(/\/+$/, '');
const N8N_KEY = process.env.N8N_KEY || '';
const n8nOn = () => !!(N8N_URL && N8N_KEY);
if (n8nOn()) console.log('N8N ligado em ' + N8N_URL);
else console.warn('AVISO: N8N não configurado (N8N_URL / N8N_KEY vazios) — a aba de automações fica em modo demonstração.');

// Hermes Agent (agente externo rodando no seu n8n). O segredo fica SÓ no servidor.
const HERMES_URL = process.env.HERMES_N8N_WEBHOOK_URL || '';
const HERMES_SECRET = process.env.HERMES_N8N_WEBHOOK_SECRET || '';
const hermesOn = () => !!HERMES_URL;

let mailer = null;
if (SMTP_HOST && SMTP_USER) {
  mailer = nodemailer.createTransport({
    host: SMTP_HOST, port: SMTP_PORT, secure: SMTP_PORT === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });
  console.log('E-mail configurado via ' + SMTP_HOST);
} else {
  console.warn('AVISO: SMTP não configurado — os códigos 2FA vão aparecer AQUI nos logs (modo teste).');
}

if (!DATABASE_URL) { console.error('Falta DATABASE_URL'); process.exit(1); }
if (!GEMINI_API_KEY) console.warn('AVISO: GEMINI_API_KEY não definida — o chat não vai funcionar até você preencher.');

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: /sslmode=require/.test(DATABASE_URL) ? { rejectUnauthorized: false } : false
});

/* ---------- cria as tabelas na primeira vez ---------- */
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id         SERIAL PRIMARY KEY,
      name       TEXT NOT NULL,
      email      TEXT UNIQUE NOT NULL,
      pass_hash  TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS profiles (
      user_id    INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      cfg        JSONB DEFAULT '{}'::jsonb,
      chat       JSONB DEFAULT '[]'::jsonb,
      updated_at TIMESTAMPTZ DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS conversations (
      id         SERIAL PRIMARY KEY,
      user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
      title      TEXT DEFAULT 'Nova conversa',
      messages   JSONB DEFAULT '[]'::jsonb,
      created_at TIMESTAMPTZ DEFAULT now(),
      updated_at TIMESTAMPTZ DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS idx_conv_user ON conversations(user_id, updated_at DESC);
    CREATE TABLE IF NOT EXISTS transactions (
      id         SERIAL PRIMARY KEY,
      user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
      kind       TEXT CHECK (kind IN ('gasto','entrada')),
      amount     NUMERIC(12,2) NOT NULL,
      category   TEXT DEFAULT 'outros',
      descr      TEXT DEFAULT '',
      happened   DATE DEFAULT CURRENT_DATE,
      created_at TIMESTAMPTZ DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS idx_tx_user ON transactions(user_id, happened DESC, id DESC);
  `);
  // 2FA: coluna verified (contas antigas já entram como verificadas para não travar)
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS verified BOOLEAN DEFAULT true;`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS auth_codes (
      email   TEXT,
      code    TEXT,
      purpose TEXT,
      expires TIMESTAMPTZ,
      tries   INT DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS trusted_devices (
      id      SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      token   TEXT,
      expires TIMESTAMPTZ
    );
  `);
  console.log('Banco pronto.');
}

/* ---------- app ---------- */
const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(express.static(join(__dirname, 'public'), {
  setHeaders: (res, p) => {
    if (p.endsWith('.html') || p.endsWith('sw.js') || p.endsWith('.webmanifest'))
      res.setHeader('Cache-Control', 'no-store, must-revalidate');
  }
}));

const sign = id => jwt.sign({ id }, JWT_SECRET, { expiresIn: '180d' });
const clean = s => String(s || '').trim();
const validEmail = e => /^\S+@\S+\.\S+$/.test(e);

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : '';
  try { req.userId = jwt.verify(t, JWT_SECRET).id; next(); }
  catch { res.status(401).json({ error: 'Faça login de novo.' }); }
}

/* ---------- helpers de 2FA por e-mail ---------- */
const genCode = () => String(Math.floor(100000 + Math.random() * 900000));

async function sendCode(email, code, kind) {
  const titulo = kind === 'login' ? 'Código para entrar no ATLAS' : 'Confirme sua conta no ATLAS';
  const text = 'Seu código do ATLAS é: ' + code + '\n\nEle vale por 10 minutos. Se não foi você, ignore este e-mail.';
  const html = `<div style="font-family:Arial,sans-serif;max-width:440px;margin:auto;background:#0A0E24;color:#EDEAF6;padding:32px;border-radius:16px">
    <div style="font-size:22px;font-weight:800;letter-spacing:-1px">ATLAS<span style="color:#E8B04B">.</span></div>
    <p style="color:#8E95BE;margin:18px 0 6px">${titulo}</p>
    <div style="font-size:38px;font-weight:800;letter-spacing:8px;color:#E8B04B;margin:10px 0">${code}</div>
    <p style="color:#8E95BE;font-size:13px;margin-top:18px">Vale por 10 minutos. Se não foi você, ignore este e-mail.</p>
  </div>`;
  if (!mailer) { console.log(`[ATLAS 2FA] Código de ${email}: ${code}`); return { sent: false }; }
  try { await mailer.sendMail({ from: MAIL_FROM, to: email, subject: titulo + ' — ' + code, text, html }); return { sent: true }; }
  catch (e) { console.error('Falha ao enviar e-mail:', e.message); console.log(`[ATLAS 2FA] Código de ${email}: ${code}`); return { sent: false }; }
}

async function issueCode(email, purpose) {
  const code = genCode();
  await pool.query('DELETE FROM auth_codes WHERE email=$1 AND purpose=$2', [email, purpose]);
  await pool.query("INSERT INTO auth_codes(email,code,purpose,expires) VALUES($1,$2,$3,now()+interval '10 minutes')",
    [email, code, purpose]);
  return sendCode(email, code, purpose);
}

async function checkCode(email, purpose, code) {
  const { rows } = await pool.query('SELECT * FROM auth_codes WHERE email=$1 AND purpose=$2', [email, purpose]);
  if (!rows.length) return { ok: false, error: 'Peça um novo código.' };
  const row = rows[0];
  if (new Date(row.expires) < new Date()) { await pool.query('DELETE FROM auth_codes WHERE email=$1 AND purpose=$2', [email, purpose]); return { ok: false, error: 'Código expirado. Peça um novo.' }; }
  if (row.tries >= 5) return { ok: false, error: 'Muitas tentativas. Peça um novo código.' };
  if (String(row.code) !== String(code || '').trim()) { await pool.query('UPDATE auth_codes SET tries=tries+1 WHERE email=$1 AND purpose=$2', [email, purpose]); return { ok: false, error: 'Código errado.' }; }
  await pool.query('DELETE FROM auth_codes WHERE email=$1 AND purpose=$2', [email, purpose]);
  return { ok: true };
}

async function authPayload(u) {
  const p = await pool.query('SELECT cfg FROM profiles WHERE user_id=$1', [u.id]);
  return { token: sign(u.id), user: { name: u.name, email: u.email }, cfg: p.rows[0]?.cfg || {} };
}

/* ---------- criar conta: cria e envia código ---------- */
app.post('/api/register', async (req, res) => {
  try {
    const name = clean(req.body.name);
    const email = clean(req.body.email).toLowerCase();
    const pass = String(req.body.password || '');
    const code = clean(req.body.code);

    if (REGISTER_CODE && code !== REGISTER_CODE)
      return res.status(403).json({ error: 'Código de convite inválido.' });
    if (!name) return res.status(400).json({ error: 'Escreva um nome.' });
    if (!validEmail(email)) return res.status(400).json({ error: 'E-mail inválido.' });
    if (pass.length < 6) return res.status(400).json({ error: 'A senha precisa de pelo menos 6 caracteres.' });

    const ex = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (ex.rowCount && ex.rows[0].verified)
      return res.status(409).json({ error: 'Esse e-mail já tem conta. Tente entrar.' });

    const hash = await bcrypt.hash(pass, 10);
    if (ex.rowCount) {
      await pool.query('UPDATE users SET name=$1, pass_hash=$2 WHERE id=$3', [name, hash, ex.rows[0].id]);
    } else {
      const ins = await pool.query('INSERT INTO users(name,email,pass_hash,verified) VALUES($1,$2,$3,false) RETURNING id', [name, email, hash]);
      await pool.query('INSERT INTO profiles(user_id) VALUES($1) ON CONFLICT DO NOTHING', [ins.rows[0].id]);
    }
    const r = await issueCode(email, 'signup');
    res.json({ step: 'code', mode: 'signup', email, delivered: r.sent });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Erro ao criar conta.' }); }
});

/* ---------- confirmar código de criação ---------- */
app.post('/api/verify-signup', async (req, res) => {
  try {
    const email = clean(req.body.email).toLowerCase();
    const c = await checkCode(email, 'signup', req.body.code);
    if (!c.ok) return res.status(400).json({ error: c.error });
    await pool.query('UPDATE users SET verified=true WHERE email=$1', [email]);
    const u = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    res.json(await authPayload(u.rows[0]));
  } catch (e) { console.error(e); res.status(500).json({ error: 'Erro ao confirmar.' }); }
});

/* ---------- entrar: senha certa envia código (2FA) ---------- */
app.post('/api/login', async (req, res) => {
  try {
    const email = clean(req.body.email).toLowerCase();
    const pass = String(req.body.password || '');
    const deviceToken = clean(req.body.deviceToken);
    const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (!rows.length) return res.status(404).json({ error: 'Conta não encontrada.' });
    const u = rows[0];
    const ok = await bcrypt.compare(pass, u.pass_hash);
    if (!ok) return res.status(401).json({ error: 'Senha errada.' });

    if (!u.verified) { const r = await issueCode(email, 'signup'); return res.json({ step: 'code', mode: 'signup', email, delivered: r.sent }); }

    if (deviceToken) {
      const d = await pool.query('SELECT 1 FROM trusted_devices WHERE user_id=$1 AND token=$2 AND expires>now()', [u.id, deviceToken]);
      if (d.rowCount) return res.json(await authPayload(u));
    }
    const r = await issueCode(email, 'login');
    res.json({ step: 'code', mode: 'login', email, delivered: r.sent });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Erro ao entrar.' }); }
});

/* ---------- confirmar código de login (com opção de confiar no aparelho) ---------- */
app.post('/api/verify-login', async (req, res) => {
  try {
    const email = clean(req.body.email).toLowerCase();
    const c = await checkCode(email, 'login', req.body.code);
    if (!c.ok) return res.status(400).json({ error: c.error });
    const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (!rows.length) return res.status(404).json({ error: 'Conta não encontrada.' });
    const payload = await authPayload(rows[0]);
    if (req.body.trustDevice) {
      const dt = crypto.randomUUID();
      await pool.query("INSERT INTO trusted_devices(user_id,token,expires) VALUES($1,$2,now()+interval '30 days')", [rows[0].id, dt]);
      payload.deviceToken = dt;
    }
    res.json(payload);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Erro ao confirmar.' }); }
});

/* ---------- reenviar código ---------- */
app.post('/api/resend', async (req, res) => {
  try {
    const email = clean(req.body.email).toLowerCase();
    const purpose = req.body.purpose === 'login' ? 'login' : 'signup';
    if (!validEmail(email)) return res.status(400).json({ error: 'E-mail inválido.' });
    const r = await issueCode(email, purpose);
    res.json({ ok: true, delivered: r.sent });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Erro ao reenviar.' }); }
});

/* ---------- carregar meus dados ---------- */
app.get('/api/state', auth, async (req, res) => {
  try {
    const u = await pool.query('SELECT name,email FROM users WHERE id=$1', [req.userId]);
    const p = await pool.query('SELECT cfg,chat FROM profiles WHERE user_id=$1', [req.userId]);
    if (!u.rowCount) return res.status(401).json({ error: 'Sessão inválida.' });
    res.json({ user: u.rows[0], cfg: p.rows[0]?.cfg || {}, chat: p.rows[0]?.chat || [] });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Erro ao carregar.' }); }
});

/* ---------- salvar meus dados (ajustes + conversa) ---------- */
app.put('/api/state', auth, async (req, res) => {
  try {
    const cfg = req.body.cfg && typeof req.body.cfg === 'object' ? req.body.cfg : {};
    const chat = Array.isArray(req.body.chat) ? req.body.chat.slice(-60) : [];
    await pool.query(
      `INSERT INTO profiles(user_id,cfg,chat,updated_at) VALUES($1,$2,$3,now())
       ON CONFLICT (user_id) DO UPDATE SET cfg=$2, chat=$3, updated_at=now()`,
      [req.userId, cfg, JSON.stringify(chat)]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Erro ao salvar.' }); }
});

/* ---------- conversas (lista lateral) ---------- */
app.get('/api/conversations', auth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id,title,updated_at FROM conversations WHERE user_id=$1 ORDER BY updated_at DESC LIMIT 200',
      [req.userId]);
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Erro ao listar conversas.' }); }
});

app.post('/api/conversations', auth, async (req, res) => {
  try {
    const title = clean(req.body.title).slice(0, 80) || 'Nova conversa';
    const { rows } = await pool.query(
      'INSERT INTO conversations(user_id,title,messages) VALUES($1,$2,$3::jsonb) RETURNING id,title,updated_at',
      [req.userId, title, '[]']);
    res.json(rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Erro ao criar conversa.' }); }
});

app.get('/api/conversations/:id', auth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id,title,messages FROM conversations WHERE id=$1 AND user_id=$2', [req.params.id, req.userId]);
    if (!rows.length) return res.status(404).json({ error: 'Conversa não encontrada.' });
    res.json(rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Erro ao abrir conversa.' }); }
});

app.put('/api/conversations/:id', auth, async (req, res) => {
  try {
    const messages = Array.isArray(req.body.messages) ? req.body.messages.slice(-200) : [];
    const title = clean(req.body.title).slice(0, 80) || 'Nova conversa';
    const r = await pool.query(
      `UPDATE conversations SET messages=$1::jsonb, title=$2, updated_at=now()
       WHERE id=$3 AND user_id=$4 RETURNING id`,
      [JSON.stringify(messages), title, req.params.id, req.userId]);
    if (!r.rowCount) return res.status(404).json({ error: 'Conversa não encontrada.' });
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Erro ao salvar conversa.' }); }
});

app.delete('/api/conversations/:id', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM conversations WHERE id=$1 AND user_id=$2', [req.params.id, req.userId]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Erro ao apagar conversa.' }); }
});

/* ---------- ponte com o Gemini (a chave nunca sai daqui) ---------- */
const MODELS = ['gemini-2.5-flash', 'gemini-2.0-flash', 'gemini-flash-latest'];
const BRAINS = {
  auto:    ['gemini-2.5-flash', 'gemini-2.0-flash', 'gemini-flash-latest'],
  esperto: ['gemini-2.5-pro', 'gemini-2.5-flash', 'gemini-2.0-flash'],
  rapido:  ['gemini-2.5-flash-lite', 'gemini-2.0-flash', 'gemini-2.5-flash']
};
const CAP = { 'gemini-2.0-flash': 8192, 'gemini-2.0-flash-lite': 8192, 'gemini-flash-latest': 8192 };

app.post('/api/chat', auth, async (req, res) => {
  if (!GEMINI_API_KEY) return res.status(503).json({ error: 'O servidor está sem a chave do Gemini configurada.' });
  const messages = Array.isArray(req.body.messages) ? req.body.messages : [];
  const search = req.body.search !== false;   // busca na internet ligada por padrão
  const now = new Date();
  const agora = now.toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo', dateStyle: 'full', timeStyle: 'short' });
  const sysBase = clean(req.body.system) || 'Você é o ATLAS, assistente pessoal. Responda em português do Brasil.';
  const system = sysBase +
    '\n\nAgora, no fuso de Brasília, é: ' + agora + '. Use esta data e hora ao responder sobre "hoje", "agora" ou o momento atual.' +
    (search ? '\nVocê tem busca na internet ativada. Para qualquer coisa atual — tempo/clima, notícias, preços, resultados, cotações — consulte a web e responda com o dado real e atualizado, citando de quando é. Não invente números.' : '');

  const want = Math.min(Math.max(+req.body.maxTokens || 4096, 256), 65536);
  const wish = BRAINS[req.body.brain] || BRAINS.auto;
  const order = [];
  wish.concat(MODELS).forEach(m => { if (order.indexOf(m) < 0) order.push(m); });
  const contents = messages.map(m => ({
    role: m.role === 'user' ? 'user' : 'model',
    parts: [{ text: String(m.text || '') }]
  }));

  async function callGemini(model, useTools) {
    const body = {
      system_instruction: { parts: [{ text: system }] },
      contents,
      generationConfig: { temperature: 0.9, maxOutputTokens: Math.min(want, CAP[model] || 65536) }
    };
    if (useTools) body.tools = [{ google_search: {} }];
    const r = await fetch('https://generativelanguage.googleapis.com/v1beta/models/' + model + ':generateContent', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-goog-api-key': GEMINI_API_KEY },
      body: JSON.stringify(body)
    });
    return { r, data: await r.json() };
  }

  let last = 'Não consegui falar com o Gemini.';
  for (const model of order) {
    let out;
    try { out = await callGemini(model, search); }
    catch { last = 'Sem conexão do servidor com o Gemini.'; continue; }
    let { r, data } = out;

    // se o modelo não aceitar a ferramenta de busca, tenta de novo sem ela
    const emsg0 = data?.error?.message || '';
    if (search && r.status === 400 && /tool|google_search|function/i.test(emsg0)) {
      try { ({ r, data } = await callGemini(model, false)); } catch { last = 'Sem conexão.'; continue; }
    }

    const emsg = data?.error?.message || '';
    if (r.status === 404 || (r.status === 400 && /model/i.test(emsg))) { last = 'Modelo indisponível na chave.'; continue; }
    if (r.status === 429) { last = 'Cota do Gemini esgotada por agora.'; continue; }
    if (!r.ok) return res.status(400).json({ error: emsg || ('Erro ' + r.status) });

    const cand = data?.candidates?.[0] || {};
    const text = (cand.content?.parts || []).map(p => p.text).filter(Boolean).join('').trim();
    if (!text) {
      if (cand.finishReason === 'SAFETY') return res.status(400).json({ error: 'O Gemini bloqueou essa resposta pelos filtros dele.' });
      last = 'Resposta vazia.'; continue;
    }
    // fontes da busca, se houver
    let sources = [];
    try {
      const chunks = cand.groundingMetadata?.groundingChunks || [];
      sources = chunks.map(c => c.web?.title).filter(Boolean).slice(0, 4);
    } catch {}
    return res.json({ text, cut: cand.finishReason === 'MAX_TOKENS', model, sources });
  }
  res.status(502).json({ error: last });
});

/* ---------- apagar minha conta ---------- */
app.delete('/api/account', auth, async (req, res) => {
  try { await pool.query('DELETE FROM users WHERE id=$1', [req.userId]); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Erro ao apagar.' }); }
});

/* ================= N8N (automações) ================= */
async function n8nCall(path, opts = {}) {
  const r = await fetch(N8N_URL + '/api/v1' + path, {
    method: opts.method || 'GET',
    headers: { 'X-N8N-API-KEY': N8N_KEY, 'Content-Type': 'application/json', accept: 'application/json' },
    body: opts.body ? JSON.stringify(opts.body) : undefined
  });
  let data = null;
  try { data = await r.json(); } catch {}
  return { ok: r.ok, status: r.status, data };
}

app.get('/api/n8n/status', auth, async (req, res) => {
  if (!n8nOn()) return res.json({ connected: false });
  try {
    const wf = await n8nCall('/workflows?limit=100');
    if (!wf.ok) return res.json({ connected: false, error: 'A chave do N8N foi recusada.' });
    const list = wf.data?.data || [];
    let runs = 0;
    try { const ex = await n8nCall('/executions?limit=1'); runs = ex.data?.data?.length ? (ex.data?.count || ex.data.data.length) : 0; } catch {}
    res.json({ connected: true, total: list.length, active: list.filter(w => w.active).length, runs });
  } catch (e) { res.json({ connected: false, error: 'N8N fora do ar.' }); }
});

app.get('/api/n8n/workflows', auth, async (req, res) => {
  if (!n8nOn()) return res.status(503).json({ error: 'N8N não conectado.' });
  try {
    const wf = await n8nCall('/workflows?limit=100');
    if (!wf.ok) return res.status(400).json({ error: 'Não consegui listar (chave/endereço do N8N).' });
    const list = (wf.data?.data || []).map(w => ({
      id: w.id, name: w.name, active: w.active,
      nodes: (w.nodes || []).length, updatedAt: w.updatedAt
    }));
    res.json({ workflows: list });
  } catch (e) { res.status(502).json({ error: 'N8N fora do ar.' }); }
});

app.post('/api/n8n/workflows/:id/:action', auth, async (req, res) => {
  if (!n8nOn()) return res.status(503).json({ error: 'N8N não conectado.' });
  const act = req.params.action === 'activate' ? 'activate' : 'deactivate';
  try {
    const r = await n8nCall('/workflows/' + req.params.id + '/' + act, { method: 'POST' });
    if (!r.ok) return res.status(400).json({ error: 'Não consegui ' + (act === 'activate' ? 'ligar' : 'desligar') + '. Talvez o fluxo precise de um gatilho válido.' });
    res.json({ ok: true, active: act === 'activate' });
  } catch (e) { res.status(502).json({ error: 'N8N fora do ar.' }); }
});

/* ---------- a IA cria um fluxo a partir da descrição ---------- */
const N8N_SYSTEM = `Você gera workflows do n8n em JSON válido. Regras:
- Responda APENAS com o JSON do workflow, sem texto, sem markdown, sem crases.
- Estrutura: {"name":"...","nodes":[...],"connections":{...},"settings":{}}.
- Cada node tem: "parameters"(objeto), "name"(único), "type", "typeVersion"(número), "position"([x,y]).
- REGRA DO GATILHO: se a tarefa é recorrente ("todo dia", "a cada hora", "às 8h") use SEMPRE "n8n-nodes-base.scheduleTrigger" com parameters apropriados — isso permite LIGAR o fluxo. Se reage a chamada externa, use "n8n-nodes-base.webhook". Só use "manualTrigger" se for realmente sob demanda.
- Depois do gatilho, adicione ao menos um node de ação, geralmente "n8n-nodes-base.set" (montar a mensagem) ou "n8n-nodes-base.httpRequest" (buscar dado de uma API pública).
- "connections" liga os nodes pelo NOME: {"NomeDoGatilho":{"main":[[{"node":"NomeDaAcao","type":"main","index":0}]]}}.
- Não invente credenciais nem use nodes que exijam login (Gmail, WhatsApp). Se pedirem envio, monte até o passo anterior e nomeie o último node "Conectar conta aqui".
- Mantenha simples, válido e LIGÁVEL.`;

function uuid() { return crypto.randomUUID(); }

app.post('/api/n8n/create', auth, async (req, res) => {
  if (!n8nOn()) return res.status(503).json({ error: 'Conecte o N8N primeiro (o dono precisa configurar).' });
  if (!GEMINI_API_KEY) return res.status(503).json({ error: 'IA sem chave configurada.' });
  const desc = clean(req.body.description);
  if (!desc) return res.status(400).json({ error: 'Descreva o que a automação deve fazer.' });

  // 1) IA gera o JSON do fluxo
  let text = '';
  try {
    const gr = await fetch('https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent', {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'x-goog-api-key': GEMINI_API_KEY },
      body: JSON.stringify({
        system_instruction: { parts: [{ text: N8N_SYSTEM }] },
        contents: [{ role: 'user', parts: [{ text: 'Crie um workflow que: ' + desc }] }],
        generationConfig: { temperature: 0.3, maxOutputTokens: 4096, responseMimeType: 'application/json' }
      })
    });
    const gd = await gr.json();
    text = (gd?.candidates?.[0]?.content?.parts || []).map(p => p.text).join('').trim();
  } catch (e) { return res.status(502).json({ error: 'A IA não respondeu. Tente de novo.' }); }

  // 2) valida e limpa o JSON
  let wf;
  try {
    text = text.replace(/^```(json)?/i, '').replace(/```$/, '').trim();
    wf = JSON.parse(text);
  } catch (e) { return res.status(422).json({ error: 'A IA gerou algo inválido. Tente descrever de forma mais simples.' }); }
  if (!wf || !Array.isArray(wf.nodes) || !wf.nodes.length)
    return res.status(422).json({ error: 'A IA não montou o fluxo. Descreva com mais detalhe (gatilho + ação).' });

  // garante campos obrigatórios
  wf.nodes.forEach((n, i) => {
    n.id = n.id || uuid();
    n.typeVersion = n.typeVersion || 1;
    n.parameters = n.parameters || {};
    n.position = Array.isArray(n.position) ? n.position : [250 + i * 220, 300];
    n.name = n.name || ('Node ' + (i + 1));
  });
  const payload = { name: (wf.name || desc).slice(0, 80), nodes: wf.nodes, connections: wf.connections || {}, settings: wf.settings || {} };

  // 3) cria no n8n (desativado, pra revisão)
  try {
    const cr = await n8nCall('/workflows', { method: 'POST', body: payload });
    if (!cr.ok) return res.status(400).json({ error: 'O N8N recusou o fluxo: ' + (cr.data?.message || cr.status) + '. Tente descrever de outro jeito.' });
    res.json({ ok: true, id: cr.data?.id, name: payload.name, nodes: payload.nodes.length,
      open: N8N_URL + '/workflow/' + (cr.data?.id || '') });
  } catch (e) { res.status(502).json({ error: 'N8N fora do ar ao criar.' }); }
});

/* ---------- IA diagnostica um fluxo (lê e explica o problema) ---------- */
app.get('/api/n8n/workflows/:id/diagnose', auth, async (req, res) => {
  if (!n8nOn()) return res.status(503).json({ error: 'N8N não conectado.' });
  try {
    const wf = await n8nCall('/workflows/' + req.params.id);
    if (!wf.ok) return res.status(400).json({ error: 'Não achei esse fluxo.' });
    const w = wf.data || {};
    const nodes = w.nodes || [];
    const triggers = nodes.filter(n => /trigger|webhook|cron|schedule/i.test(n.type || ''));
    const manual = nodes.some(n => /manualTrigger/i.test(n.type || ''));
    const activatable = triggers.some(n => !/manualTrigger/i.test(n.type || ''));

    // resumo técnico pra IA explicar
    const resumo = nodes.map(n => '- ' + (n.name || '?') + ' (' + (n.type || '?').replace('n8n-nodes-base.', '') + ')').join('\n') || '(vazio)';
    let report = '';
    if (GEMINI_API_KEY) {
      try {
        const gr = await fetch('https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent', {
          method: 'POST', headers: { 'Content-Type': 'application/json', 'x-goog-api-key': GEMINI_API_KEY },
          body: JSON.stringify({
            system_instruction: { parts: [{ text: 'Você é o ATLAS. Explique em português simples, em até 4 frases, o estado de um fluxo do n8n e o que falta para funcionar/ligar. Seja prático e gentil. Não use jargão técnico. Se faltar gatilho automático (schedule/webhook), diga que ele só roda no botão Executar. Se algum passo pedir conta/login, avise que precisa conectar a conta no n8n.' }] },
            contents: [{ role: 'user', parts: [{ text: `Fluxo "${w.name}". Ativo: ${w.active}. Passos:\n${resumo}\n\nTem gatilho automático? ${activatable ? 'sim' : 'não'}. Tem gatilho manual? ${manual ? 'sim' : 'não'}.` }] }],
            generationConfig: { temperature: 0.4, maxOutputTokens: 500 }
          })
        });
        const gd = await gr.json();
        report = (gd?.candidates?.[0]?.content?.parts || []).map(p => p.text).join('').trim();
      } catch {}
    }
    if (!report) {
      report = nodes.length === 0
        ? 'Esse fluxo está **vazio** — não tem nenhum passo. Adicione um começo (gatilho) e uma ação para ele funcionar.'
        : activatable ? 'O fluxo tem um gatilho automático e pode ser ligado. Se não liga, algum passo pode estar pedindo uma conta conectada.'
        : 'Esse fluxo só tem começo manual, então roda no botão **Executar** — ele não fica "ligado" sozinho. Para ligar automático, precisa de um gatilho de agendamento ou webhook.';
    }
    res.json({ report, activatable, empty: nodes.length === 0, open: N8N_URL + '/workflow/' + req.params.id });
  } catch (e) { res.status(502).json({ error: 'N8N fora do ar.' }); }
});

/* ---------- enviar e-mail de verdade (via Brevo) ---------- */
const sendCounts = {};  // limite simples por usuário por dia
app.post('/api/send-email', auth, async (req, res) => {
  if (!mailer) return res.status(503).json({ error: 'O servidor ainda não tem e-mail configurado (SMTP). O dono precisa preencher no EasyPanel.' });
  const to = clean(req.body.to).toLowerCase();
  const subject = clean(req.body.subject).slice(0, 160) || '(sem assunto)';
  const body = String(req.body.body || '').slice(0, 6000);
  if (!validEmail(to)) return res.status(400).json({ error: 'O e-mail de quem vai receber está inválido.' });
  if (!body.trim()) return res.status(400).json({ error: 'Escreva a mensagem antes de enviar.' });

  const day = new Date().toISOString().slice(0, 10);
  const key = req.userId + ':' + day;
  sendCounts[key] = (sendCounts[key] || 0) + 1;
  if (sendCounts[key] > 30) return res.status(429).json({ error: 'Você já enviou muitos e-mails hoje. Tente amanhã.' });

  try {
    const u = await pool.query('SELECT email,name FROM users WHERE id=$1', [req.userId]);
    const nome = u.rows[0]?.name || 'ATLAS';
    const replyTo = u.rows[0]?.email;
    const html = `<div style="font-family:Arial,sans-serif;font-size:15px;line-height:1.6;color:#222">${body.replace(/\n/g, '<br>')}<hr style="border:none;border-top:1px solid #eee;margin:20px 0"><div style="font-size:12px;color:#999">Enviado por ${nome} via ATLAS</div></div>`;
    await mailer.sendMail({ from: `"${nome} (via ATLAS)" <${MAIL_FROM}>`, to, replyTo, subject, text: body, html });
    res.json({ ok: true });
  } catch (e) { console.error('send-email:', e.message); res.status(502).json({ error: 'Não consegui enviar agora. Tente de novo.' }); }
});

/* ---------- IA escreve o e-mail ---------- */
app.post('/api/draft-email', auth, async (req, res) => {
  if (!GEMINI_API_KEY) return res.status(503).json({ error: 'IA sem chave.' });
  const pedido = clean(req.body.prompt);
  if (!pedido) return res.status(400).json({ error: 'Diga sobre o que é o e-mail.' });
  try {
    const gr = await fetch('https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent', {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'x-goog-api-key': GEMINI_API_KEY },
      body: JSON.stringify({
        system_instruction: { parts: [{ text: 'Você escreve e-mails em português do Brasil, claros e educados. Responda em JSON: {"assunto":"...","corpo":"..."} e nada mais. O corpo deve ter saudação e despedida naturais.' }] },
        contents: [{ role: 'user', parts: [{ text: pedido }] }],
        generationConfig: { temperature: 0.7, maxOutputTokens: 1200, responseMimeType: 'application/json' }
      })
    });
    const gd = await gr.json();
    let t = (gd?.candidates?.[0]?.content?.parts || []).map(p => p.text).join('').trim().replace(/^```(json)?/i, '').replace(/```$/, '');
    const j = JSON.parse(t);
    res.json({ subject: j.assunto || '', body: j.corpo || '' });
  } catch (e) { res.status(502).json({ error: 'A IA não conseguiu escrever agora.' }); }
});

/* ================= HERMES AGENT (agente externo via n8n) ================= */
app.get('/api/hermes/status', auth, (req, res) => res.json({ connected: hermesOn() }));

app.post('/api/hermes/chat', auth, async (req, res) => {
  if (!hermesOn()) return res.status(503).json({ error: 'O agente Hermes ainda não foi conectado pelo dono.' });
  const message = clean(req.body.message);
  const sessionId = clean(req.body.sessionId) || ('sess-' + req.userId);
  if (!message) return res.status(400).json({ error: 'Escreva uma mensagem.' });
  try {
    const r = await fetch(HERMES_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Hermes-Secret': HERMES_SECRET },
      body: JSON.stringify({ message, sessionId })
    });
    let data = null;
    try { data = await r.json(); } catch {}
    if (!r.ok) return res.status(502).json({ error: 'O agente não respondeu (erro ' + r.status + ').' });
    // aceita vários formatos comuns de resposta do n8n
    const reply = (data && (data.reply || data.output || data.text || data.message || data.answer)) ||
      (typeof data === 'string' ? data : '') || 'O agente respondeu, mas sem texto.';
    res.json({ reply: String(reply), sessionId });
  } catch (e) { console.error('hermes:', e.message); res.status(502).json({ error: 'Não consegui falar com o agente agora.' }); }
});

/* ================= AGENTE CRIATIVO (letras, paródia, roteiro) ================= */
const AGENT_KINDS = {
  musica: 'Você é um compositor. Escreva uma LETRA de música original e completa em português do Brasil sobre o tema pedido: título, e estrofes com [Verso], [Refrão], [Ponte] marcados. Rima natural. Só a letra, sem explicação.',
  parodia: 'Você é um comediante. Escreva uma LETRA de paródia ORIGINAL e engraçada em português sobre o tema pedido (não copie letras existentes; crie do zero no clima pedido). Marque [Verso] e [Refrão]. Só a letra.',
  roteiro: 'Você é um roteirista. Escreva um roteiro curto e envolvente em português sobre o tema pedido, com cenas marcadas (CENA 1, etc.), descrição e diálogos. Só o roteiro.',
  poema: 'Você é um poeta. Escreva um poema original e bonito em português sobre o tema pedido. Só o poema.'
};
app.post('/api/agent/create', auth, async (req, res) => {
  if (!GEMINI_API_KEY) return res.status(503).json({ error: 'IA sem chave.' });
  const kind = AGENT_KINDS[req.body.kind] ? req.body.kind : 'musica';
  const theme = clean(req.body.theme);
  if (!theme) return res.status(400).json({ error: 'Diga o tema.' });
  try {
    const gr = await fetch('https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent', {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'x-goog-api-key': GEMINI_API_KEY },
      body: JSON.stringify({
        system_instruction: { parts: [{ text: AGENT_KINDS[kind] }] },
        contents: [{ role: 'user', parts: [{ text: 'Tema: ' + theme }] }],
        generationConfig: { temperature: 1.0, maxOutputTokens: 2048 }
      })
    });
    const gd = await gr.json();
    const text = (gd?.candidates?.[0]?.content?.parts || []).map(p => p.text).filter(Boolean).join('').trim();
    if (!text) return res.status(502).json({ error: 'A IA não gerou nada. Tente outro tema.' });
    res.json({ text });
  } catch (e) { res.status(502).json({ error: 'A IA não respondeu agora.' }); }
});

/* ================= FINANÇAS (agente financeiro) ================= */
// resumo: saldo, gastos e entradas do mês, últimos lançamentos
app.get('/api/finance/summary', auth, async (req, res) => {
  try {
    const tot = await pool.query(
      `SELECT COALESCE(SUM(CASE WHEN kind='entrada' THEN amount ELSE -amount END),0) AS saldo FROM transactions WHERE user_id=$1`, [req.userId]);
    const mes = await pool.query(
      `SELECT COALESCE(SUM(CASE WHEN kind='gasto' THEN amount END),0) AS gastos,
              COALESCE(SUM(CASE WHEN kind='entrada' THEN amount END),0) AS entradas
       FROM transactions WHERE user_id=$1 AND date_trunc('month',happened)=date_trunc('month',CURRENT_DATE)`, [req.userId]);
    const last = await pool.query(
      `SELECT id,kind,amount,category,descr,happened FROM transactions WHERE user_id=$1 ORDER BY happened DESC,id DESC LIMIT 15`, [req.userId]);
    const lastGasto = await pool.query(
      `SELECT happened FROM transactions WHERE user_id=$1 AND kind='gasto' ORDER BY happened DESC,id DESC LIMIT 1`, [req.userId]);
    res.json({
      saldo: Number(tot.rows[0].saldo),
      gastosMes: Number(mes.rows[0].gastos), entradasMes: Number(mes.rows[0].entradas),
      ultimoGasto: lastGasto.rows[0]?.happened || null,
      lancamentos: last.rows.map(r => ({ ...r, amount: Number(r.amount) }))
    });
  } catch (e) { console.error('fin summary:', e.message); res.status(500).json({ error: 'Não consegui carregar o resumo.' }); }
});

// registrar direto (botões rápidos)
app.post('/api/finance/tx', auth, async (req, res) => {
  const kind = req.body.kind === 'entrada' ? 'entrada' : 'gasto';
  const amount = Math.round(Number(req.body.amount) * 100) / 100;
  const category = clean(req.body.category).slice(0, 40) || 'outros';
  const descr = clean(req.body.descr).slice(0, 140);
  if (!isFinite(amount) || amount <= 0) return res.status(400).json({ error: 'Valor inválido.' });
  if (amount > 100000000) return res.status(400).json({ error: 'Valor grande demais.' });
  try {
    await pool.query(`INSERT INTO transactions (user_id,kind,amount,category,descr) VALUES ($1,$2,$3,$4,$5)`,
      [req.userId, kind, amount, category, descr]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Não consegui salvar.' }); }
});

app.delete('/api/finance/tx/:id', auth, async (req, res) => {
  try {
    await pool.query(`DELETE FROM transactions WHERE id=$1 AND user_id=$2`, [req.params.id, req.userId]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Não consegui apagar.' }); }
});

// chat financeiro: texto natural -> IA extrai e registra -> responde com conselho
app.post('/api/finance/chat', auth, async (req, res) => {
  if (!GEMINI_API_KEY) return res.status(503).json({ error: 'IA sem chave.' });
  const msg = clean(req.body.message).slice(0, 800);
  if (!msg) return res.status(400).json({ error: 'Escreva algo.' });
  try {
    // contexto real do usuário
    const s = await pool.query(
      `SELECT COALESCE(SUM(CASE WHEN kind='entrada' THEN amount ELSE -amount END),0) AS saldo FROM transactions WHERE user_id=$1`, [req.userId]);
    const saldoAtual = Number(s.rows[0].saldo);

    const gr = await fetch('https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent', {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'x-goog-api-key': GEMINI_API_KEY },
      body: JSON.stringify({
        system_instruction: { parts: [{ text:
`Você é o agente financeiro do ATLAS. O usuário fala sobre dinheiro em linguagem natural.
Responda SEMPRE em JSON puro: {"transacoes":[{"kind":"gasto"|"entrada","amount":numero,"category":"mercado|contas|transporte|lazer|salario|saude|outros","descr":"texto curto"}],"resposta":"sua fala pro usuário"}.
- Se a mensagem registra gasto/entrada (ex: "gastei 50 no mercado", "recebi 2000 de salário"), preencha transacoes (pode ter mais de uma).
- Se for pergunta ou pedido de conselho, transacoes=[] e responda em "resposta" com base no saldo informado.
- "resposta" deve ser curta (1-3 frases), amigável, em português do Brasil, e pode incluir um conselho prático sobre gastar ou economizar.
- Nunca invente transação que o usuário não citou. Valores em reais.` }] },
        contents: [{ role: 'user', parts: [{ text: `Saldo atual do usuário: R$ ${saldoAtual.toFixed(2)}.\nMensagem: ${msg}` }] }],
        generationConfig: { temperature: 0.4, maxOutputTokens: 800, responseMimeType: 'application/json' }
      })
    });
    const gd = await gr.json();
    let t = (gd?.candidates?.[0]?.content?.parts || []).map(p => p.text).join('').trim().replace(/^```(json)?/i, '').replace(/```$/, '');
    let j; try { j = JSON.parse(t); } catch { j = { transacoes: [], resposta: t.slice(0, 400) || 'Não entendi, tente de novo.' }; }

    const salvas = [];
    for (const tx of (Array.isArray(j.transacoes) ? j.transacoes.slice(0, 10) : [])) {
      const kind = tx.kind === 'entrada' ? 'entrada' : 'gasto';
      const amount = Math.round(Number(tx.amount) * 100) / 100;
      if (!isFinite(amount) || amount <= 0 || amount > 100000000) continue;
      await pool.query(`INSERT INTO transactions (user_id,kind,amount,category,descr) VALUES ($1,$2,$3,$4,$5)`,
        [req.userId, kind, amount, clean(tx.category).slice(0, 40) || 'outros', clean(tx.descr).slice(0, 140)]);
      salvas.push({ kind, amount });
    }
    res.json({ reply: String(j.resposta || 'Anotado!'), saved: salvas });
  } catch (e) { console.error('fin chat:', e.message); res.status(502).json({ error: 'A IA não respondeu agora.' }); }
});

app.get('/api/health', (req, res) => res.json({ ok: true, version: 'atlas-v7-financas', n8n: n8nOn(), email: !!mailer, hermes: hermesOn() }));

initDb()
  .then(() => app.listen(PORT, () => console.log('ATLAS no ar na porta ' + PORT)))
  .catch(e => { console.error('Falha ao iniciar o banco:', e); process.exit(1); });
