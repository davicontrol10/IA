# ATLAS — Stack completa com Docker Compose

Este `docker-compose.yml` sobe **tudo de uma vez** num servidor com Docker:

- **atlas** — a aplicação (app + backend)
- **atlas-db** — banco Postgres do ATLAS
- **atlas-n8n** — o N8N (automações)
- **atlas-n8n-db** — banco Postgres do N8N

Os quatro já vêm ligados entre si. Você não precisa configurar rede: dentro do
compose, o ATLAS fala com o N8N pelo endereço interno `http://atlas-n8n:5678`, e
cada app fala com seu banco pelo nome do serviço.

---

## Quando usar isto

- Se você quer subir a stack inteira num **VPS com Docker** (fora do EasyPanel),
  com um comando só.
- Se quer um **backup** da configuração inteira num arquivo.
- Se vai **levar o projeto** pra outro servidor sem refazer tudo na mão.

> Observação: no **EasyPanel** você já tem cada peça criada pela interface — não
> precisa deste compose lá. Ele é para rodar Docker "puro" você mesmo.

---

## Como subir (passo a passo)

Pré-requisito: um servidor Linux com **Docker** e **Docker Compose** instalados.

1. Copie a pasta do projeto para o servidor (o `Dockerfile`, o `docker-compose.yml`,
   a pasta `public/`, o `server.js`, o `package.json`).

2. Copie o arquivo de exemplo de variáveis e preencha:

   ```bash
   cp .env.stack.example .env
   nano .env
   ```

   Preencha as senhas dos bancos, a chave do Gemini, o Brevo, e o `N8N_HOST`
   (o domínio público do seu N8N). Deixe `N8N_KEY` vazio por enquanto.

3. Suba a stack:

   ```bash
   docker compose up -d
   ```

   A primeira vez baixa as imagens e monta tudo (uns minutos).

4. **Pegue a chave do N8N.** Abra o N8N no navegador (no domínio que você pôs em
   `N8N_HOST`), crie a conta de dono, vá em **Settings → n8n API → Create API key**,
   copie a chave.

5. Cole a chave em `N8N_KEY` no `.env` e reinicie só o app:

   ```bash
   docker compose up -d atlas
   ```

Pronto. O ATLAS abre na porta **3000** e o N8N na **5678**.

---

## Domínios e HTTPS

O compose expõe as portas `3000` (ATLAS) e `5678` (N8N). Para colocar domínio com
cadeado (HTTPS), use um proxy reverso na frente (Traefik, Caddy ou Nginx Proxy
Manager). Aponte:

- `atlas.seudominio.com` → porta 3000
- `n8n.seudominio.com`  → porta 5678  (e é este que vai em `N8N_HOST`)

Sem HTTPS, o "Instalar app" (PWA) e alguns recursos não funcionam.

---

## Comandos úteis

```bash
docker compose ps            # ver o que está rodando
docker compose logs -f atlas # ver os logs do app
docker compose logs -f atlas-n8n
docker compose down          # parar tudo (os dados ficam salvos nos volumes)
docker compose pull          # baixar versões novas das imagens
docker compose up -d         # aplicar
```

## Backup

Os dados ficam em volumes do Docker (`atlas_db_data`, `n8n_db_data`, `n8n_data`).
Para backup do banco do ATLAS:

```bash
docker compose exec atlas-db pg_dump -U atlas atlas > backup_atlas.sql
```

## Guarde bem

- `N8N_ENCRYPTION_KEY` — se perder, o N8N perde acesso às credenciais salvas.
- As senhas dos bancos e o `JWT_SECRET`.
- Nunca suba o `.env` preenchido para o GitHub.
