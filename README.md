# Portal da Intranet — sistema de login

Front-end em HTML/JS puro + back-end Node.js/Express + SQLite. Autenticação com JWT de curta duração,
refresh tokens rotativos e revogação imediata de sessões.

## Estrutura

```
intranet-auth/
├── db/schema.sql               # esquema (users, sessions, refresh_tokens + índices)
├── public/                     # front-end (servido pelo próprio Express, mesma origem)
│   ├── index.html              # landing page
│   ├── login.html  register.html  dashboard.html
│   ├── css/styles.css
│   └── js/ api.js ui.js validators.js login.js register.js dashboard.js
├── src/
│   ├── server.js               # bootstrap, limpeza periódica, shutdown gracioso
│   ├── app.js                  # composição das camadas + middlewares globais
│   ├── config/                 # leitura e validação das variáveis de ambiente
│   ├── routes/                 # definição das rotas
│   ├── controllers/            # HTTP <-> serviços (cookies, status codes)
│   ├── services/               # regras de negócio (auth, senha, tokens)
│   ├── repositories/           # acesso a dados (SQL parametrizado)
│   ├── middleware/             # authenticate, csrf, rateLimiters, validate, errorHandler
│   ├── validators/             # schemas zod
│   ├── db/database.js
│   └── utils/                  # AppError, logger, time
└── tests/                      # 48 testes (node:test + supertest), ~99% de cobertura de linhas
```

## Como executar

Requisitos: Node.js 20+.

```bash
npm install
cp .env.example .env
npm run gen-secret              # copie o valor para JWT_SECRET no .env
npm start                       # http://localhost:3000   (ou: npm run dev)
npm test                        # testes automatizados
npm run test:coverage           # testes + cobertura
```

Se a intranet for acessada por outro endereço (ex.: `https://portal.empresa.local`), inclua-o em
`ALLOWED_ORIGINS`. Ele é usado no CORS e na verificação anti-CSRF.

## API

| Método | Rota                    | Auth          | Descrição                                          |
|--------|-------------------------|---------------|----------------------------------------------------|
| POST   | `/api/auth/register`    | —             | Cadastro (201; 400 validação; 409 duplicidade)     |
| POST   | `/api/auth/login`       | —             | Retorna `accessToken` e define cookie do refresh   |
| POST   | `/api/auth/refresh`     | cookie        | Rotaciona o refresh token e emite novo access token|
| POST   | `/api/auth/logout`      | cookie        | Revoga a sessão atual (idempotente, 204)           |
| POST   | `/api/auth/logout-all`  | Bearer        | Revoga todas as sessões do usuário (204)           |
| GET    | `/api/users/me`         | Bearer        | Dados do usuário autenticado                       |
| GET    | `/api/health`           | —             | Verificação de saúde                               |

Erros seguem sempre `{ "error": { "code", "message", "details?", "requestId" } }`.
Toda requisição que muda estado deve enviar `X-Requested-With: XMLHttpRequest` (o front-end já faz isso).

## Decisões de segurança

**Senhas** — Argon2id (m=19 MiB, t=2, p=1, valores mínimos recomendados pela OWASP), sal aleatório por senha
embutido no hash. Tamanho máximo de 128 caracteres evita DoS pelo custo do hash. Para usuário inexistente
o servidor executa uma verificação fictícia, igualando o tempo de resposta (sem enumeração por timing).

**Tokens**
- *Access token*: JWT HS256, 15 min, com `iss`, `aud`, `exp` e `sid` (id da sessão). O algoritmo é fixado
  na verificação (bloqueia `alg: none`). O front guarda **só em memória**.
- *Refresh token*: valor opaco de 384 bits em cookie `HttpOnly; SameSite=Strict; Path=/api/auth`
  (+ `Secure` em produção). No banco fica apenas o SHA-256.
- *Rotação com detecção de reuso*: cada refresh token vale uma vez. Se um já usado reaparecer (indício de
  roubo), a sessão inteira é revogada.
- *Revogação imediata*: o JWT carrega o `sid` e `authenticate` confere se a sessão está ativa. Logout
  invalida o access token na hora, sem esperar os 15 minutos. A sessão tem validade absoluta de 7 dias.

**Injeção** — todas as consultas usam parâmetros ligados (`?`). Entradas passam por allowlist (zod `.strict()`);
username, e-mail e telefone não aceitam `< > ' "`, então nada perigoso chega ao banco.

**XSS** — CSP sem `'unsafe-inline'` (por isso não há `<script>` nem `style=` inline), `textContent` em vez
de `innerHTML`, access token fora do `localStorage`, refresh token inacessível ao JavaScript.

**CSRF** — três camadas: `SameSite=Strict`, checagem do cabeçalho `Origin` contra `ALLOWED_ORIGINS` e
cabeçalho customizado obrigatório (um `<form>` externo não consegue enviá-lo; um `fetch` externo cairia
no preflight, que o CORS nega).

**Força bruta** — dois limitadores independentes no login, contando só as falhas: por IP (20/15 min) e
por nome de usuário informado (5/15 min, qualquer IP). Cadastro limitado a 10/hora por IP. Teto geral da API.
O limite por usuário usa o texto enviado, exista a conta ou não, então não permite descobrir contas.

**Cabeçalhos/CORS** — Helmet (CSP, nosniff, Referrer-Policy, COOP, HSTS quando há HTTPS), CORS com lista
de origens, `Cache-Control: no-store` na API, corpo JSON limitado a 10 KB.

**Logs e respostas** — o hash nunca sai do repositório; erros 500 devolvem mensagem genérica (stack só no log);
cabeçalhos `Authorization`/`Cookie`/`Set-Cookie` são mascarados e corpos de requisição nunca são registrados.

## Limitações conhecidas (e como evoluir)

- **Duplicidade no cadastro revela que um usuário/e-mail existe.** É exigido pelo requisito; o risco é
  reduzido pelo limite de cadastros. Para eliminar, use confirmação por e-mail.
- **Bloqueio por usuário permite que alguém bloqueie a conta de outra pessoa** por 15 min. Em intranet é um
  trade-off aceitável; alternativas: CAPTCHA ou atraso progressivo.
- **Rate limit em memória** vale para uma única instância. Com várias, use um store compartilhado (Redis).
- **Duas abas renovando o mesmo token ao mesmo tempo** podem acionar a detecção de reuso e encerrar a sessão.
- **HTTPS:** em produção, termine TLS no proxy reverso (nginx etc.), configure `TRUST_PROXY` e mantenha
  `COOKIE_SECURE=true`. Sem HTTPS, senhas e tokens trafegam em texto claro na rede.
- Não há recuperação de senha, verificação de e-mail nem papéis/permissões: são os próximos passos naturais.
- Rotacione `JWT_SECRET` periodicamente (isso derruba os access tokens ativos; os refresh tokens continuam válidos).
