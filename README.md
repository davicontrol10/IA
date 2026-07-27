# ATLAS — backend + site

Isto roda tudo no seu servidor pelo EasyPanel: o site, o login, o banco de dados
e a ponte com o Gemini. A sua chave do Gemini fica escondida no servidor — ninguém
que abrir o site consegue vê-la. E a conta funciona em qualquer aparelho: entrou no
PC, os mesmos dados aparecem no celular.

---

## O que você vai criar no EasyPanel (3 coisas)

1. Um banco **Postgres**
2. Um **app** (este código Node)
3. As **variáveis de ambiente** que ligam os dois

Leva uns 10 minutos.

---

## Passo 1 — Criar o Postgres

1. No seu projeto do EasyPanel, clique em **+ Service** → **Postgres**.
2. Dê um nome, por exemplo `atlas-db`.
3. Anote a **senha** que ele gerar (ou defina uma).
4. Depois de criar, abra o serviço e copie a **connection string interna**.
   Ela tem esta cara:

       postgres://postgres:SENHA@atlas-db:5432/postgres

   (o `atlas-db` é o nome do serviço; a porta interna é 5432)

---

## Passo 2 — Subir este código como app

Você tem duas formas. A mais fácil é pelo GitHub.

**Opção A — GitHub (recomendada)**
1. Crie um repositório no GitHub e suba estes arquivos
   (`server.js`, `package.json`, `Dockerfile`, e a pasta `public/`).
2. No EasyPanel: **+ Service** → **App**.
3. Em **Source**, escolha **GitHub** e aponte para o seu repositório.
4. O EasyPanel detecta o `Dockerfile` e faz o resto.

**Opção B — Sem GitHub**
1. **+ Service** → **App**.
2. Em **Source**, escolha **Dockerfile** / upload, e envie a pasta.

---

## Passo 3 — Preencher as variáveis de ambiente

No app, abra a aba **Environment** e adicione (veja o arquivo `.env.example`):

    DATABASE_URL   = a connection string do Passo 1
    GEMINI_API_KEY = sua chave do Gemini (pegue em aistudio.google.com/apikey)
    JWT_SECRET     = uma frase secreta longa e aleatória (invente uma)
    REGISTER_CODE  = deixe vazio, OU ponha um código se quiser controlar quem cria conta
    PORT           = 3000

Salve. O EasyPanel vai reiniciar o app.

---

## Passo 4 — Ligar o domínio

1. Na aba **Domains** do app, adicione um domínio (ou use o subdomínio que o
   EasyPanel oferece).
2. Marque a opção de **HTTPS / Let's Encrypt**.
3. Aponte a porta do domínio para **3000**.

Pronto. Abra o endereço no navegador: o ATLAS aparece, você cria sua conta e usa.

---

## Dicas

- **A chave do Gemini some do site?** Sim. Agora ela vive só no servidor. O celular
  fala com o seu app, e o seu app fala com o Gemini. Quem abrir "ver código-fonte"
  não acha chave nenhuma.

- **Quero que só eu (ou amigos) possam criar conta.** Preencha `REGISTER_CODE` com
  uma palavra secreta. Na tela de criar conta, vai aparecer um campo pedindo o código.

- **Papel de parede com foto sua** não sobe pra nuvem (imagem é pesada); ela fica
  salva no próprio aparelho. Todo o resto (ajustes, dados, conversas) sincroniza.

- **Backup do banco.** No EasyPanel existe o template *Postgres Backup* que manda
  cópias automáticas pro S3. Vale ligar depois.

- **Trocar a chave do Gemini** é só mudar `GEMINI_API_KEY` e reiniciar. Ninguém
  precisa fazer nada no celular.

---

## Rodar no seu PC pra testar (opcional)

Precisa de Node 18+ e um Postgres rodando.

    npm install
    DATABASE_URL="postgres://postgres@localhost:5432/postgres" \
    GEMINI_API_KEY="sua-chave" \
    JWT_SECRET="qualquercoisa" \
    node server.js

Abra http://localhost:3000
