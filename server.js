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
    if (p.endsWith('.html')) res.setHeader('Cache-Control', 'no-store, must-revalidate');
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

app.get('/api/health', (req, res) => res.json({ ok: true, version: 'atlas-v3-conversas' }));

initDb()
  .then(() => app.listen(PORT, () => console.log('ATLAS no ar na porta ' + PORT)))
  .catch(e => { console.error('Falha ao iniciar o banco:', e); process.exit(1); });
