import express from 'express';
import pkg from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
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
  `);
  console.log('Banco pronto.');
}

/* ---------- app ---------- */
const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(express.static(join(__dirname, 'public')));

const sign = id => jwt.sign({ id }, JWT_SECRET, { expiresIn: '180d' });
const clean = s => String(s || '').trim();
const validEmail = e => /^\S+@\S+\.\S+$/.test(e);

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : '';
  try { req.userId = jwt.verify(t, JWT_SECRET).id; next(); }
  catch { res.status(401).json({ error: 'Faça login de novo.' }); }
}

/* ---------- criar conta ---------- */
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

    const dup = await pool.query('SELECT 1 FROM users WHERE email=$1', [email]);
    if (dup.rowCount) return res.status(409).json({ error: 'Esse e-mail já tem conta. Tente entrar.' });

    const hash = await bcrypt.hash(pass, 10);
    const { rows } = await pool.query(
      'INSERT INTO users(name,email,pass_hash) VALUES($1,$2,$3) RETURNING id', [name, email, hash]);
    const id = rows[0].id;
    await pool.query('INSERT INTO profiles(user_id) VALUES($1)', [id]);
    res.json({ token: sign(id), user: { name, email }, cfg: {}, chat: [] });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Erro ao criar conta.' }); }
});

/* ---------- entrar ---------- */
app.post('/api/login', async (req, res) => {
  try {
    const email = clean(req.body.email).toLowerCase();
    const pass = String(req.body.password || '');
    const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (!rows.length) return res.status(404).json({ error: 'Conta não encontrada.' });
    const ok = await bcrypt.compare(pass, rows[0].pass_hash);
    if (!ok) return res.status(401).json({ error: 'Senha errada.' });
    const p = await pool.query('SELECT cfg,chat FROM profiles WHERE user_id=$1', [rows[0].id]);
    res.json({
      token: sign(rows[0].id),
      user: { name: rows[0].name, email: rows[0].email },
      cfg: p.rows[0]?.cfg || {}, chat: p.rows[0]?.chat || []
    });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Erro ao entrar.' }); }
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

/* ---------- ponte com o Gemini (a chave nunca sai daqui) ---------- */
const MODELS = ['gemini-2.5-flash', 'gemini-2.0-flash', 'gemini-flash-latest'];
const BRAINS = {
  auto:    ['gemini-2.5-flash', 'gemini-2.0-flash', 'gemini-flash-latest'],
  esperto: ['gemini-2.5-pro', 'gemini-2.5-flash', 'gemini-2.0-flash'],
  rapido:  ['gemini-2.5-flash-lite', 'gemini-2.0-flash-lite', 'gemini-2.0-flash']
};
const CAP = { 'gemini-2.0-flash': 8192, 'gemini-2.0-flash-lite': 8192, 'gemini-flash-latest': 8192 };

app.post('/api/chat', auth, async (req, res) => {
  if (!GEMINI_API_KEY) return res.status(503).json({ error: 'O servidor está sem a chave do Gemini configurada.' });
  const messages = Array.isArray(req.body.messages) ? req.body.messages : [];
  const system = clean(req.body.system) || 'Você é o ATLAS, assistente pessoal. Responda em português do Brasil.';
  const want = Math.min(Math.max(+req.body.maxTokens || 4096, 256), 65536);
  const wish = BRAINS[req.body.brain] || BRAINS.auto;

  const order = [];
  wish.concat(MODELS).forEach(m => { if (order.indexOf(m) < 0) order.push(m); });
  const contents = messages.map(m => ({
    role: m.role === 'user' ? 'user' : 'model',
    parts: [{ text: String(m.text || '') }]
  }));

  let last = 'Não consegui falar com o Gemini.';
  for (const model of order) {
    const body = {
      system_instruction: { parts: [{ text: system }] },
      contents,
      generationConfig: { temperature: 0.9, maxOutputTokens: Math.min(want, CAP[model] || 65536) }
    };
    let r, data;
    try {
      r = await fetch('https://generativelanguage.googleapis.com/v1beta/models/' + model + ':generateContent', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-goog-api-key': GEMINI_API_KEY },
        body: JSON.stringify(body)
      });
      data = await r.json();
    } catch { last = 'Sem conexão do servidor com o Gemini.'; continue; }

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
    return res.json({ text, cut: cand.finishReason === 'MAX_TOKENS', model });
  }
  res.status(502).json({ error: last });
});

/* ---------- apagar minha conta ---------- */
app.delete('/api/account', auth, async (req, res) => {
  try { await pool.query('DELETE FROM users WHERE id=$1', [req.userId]); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Erro ao apagar.' }); }
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

initDb()
  .then(() => app.listen(PORT, () => console.log('ATLAS no ar na porta ' + PORT)))
  .catch(e => { console.error('Falha ao iniciar o banco:', e); process.exit(1); });
