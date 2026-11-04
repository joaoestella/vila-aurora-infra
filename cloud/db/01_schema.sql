-- Banco da plataforma nova (Rede Vila Aurora). Dados sintéticos.
\connect vila
CREATE TABLE telemetria (
  id bigserial PRIMARY KEY,
  msg_id text UNIQUE NOT NULL,
  espaco text NOT NULL,
  dispositivo text NOT NULL,
  seq bigint NOT NULL,
  tipo text NOT NULL,           -- telemetry | state | event
  ts timestamptz NOT NULL,
  recebido_em timestamptz NOT NULL DEFAULT now(),
  payload jsonb NOT NULL
);
CREATE INDEX ix_tel_disp_seq ON telemetria(dispositivo, seq);
CREATE INDEX ix_tel_ts ON telemetria(ts);

-- operadores do painel: só login, nome de exibição e perfil (minimização). Senha com hash e segredo TOTP.
CREATE TABLE operadores (
  id serial PRIMARY KEY,
  login text UNIQUE NOT NULL,
  nome_exibicao text NOT NULL,
  perfil text NOT NULL CHECK (perfil IN ('operador','tecnico','coordenacao','auditor')),
  senha_hash text NOT NULL,
  totp_secret text NOT NULL,
  ativo boolean NOT NULL DEFAULT true,
  falhas int NOT NULL DEFAULT 0,
  bloqueado_ate timestamptz
);

-- histórico de acessos às portas: o crachá chega pseudonimizado pela borda (HMAC), nunca em claro
CREATE TABLE acessos (
  id bigserial PRIMARY KEY,
  ts timestamptz NOT NULL,
  espaco text NOT NULL,
  porta text NOT NULL,
  cracha_ps text NOT NULL,
  resultado text NOT NULL CHECK (resultado IN ('granted','denied'))
);
CREATE INDEX ix_acessos_ts ON acessos(ts);

CREATE TABLE aprovacoes (
  id serial PRIMARY KEY,
  pedido jsonb NOT NULL,
  pedido_por text NOT NULL,
  origem text NOT NULL,         -- painel | soar
  status text NOT NULL DEFAULT 'pendente' CHECK (status IN ('pendente','aprovado','negado','expirado')),
  decidido_por text,
  decidido_em timestamptz,
  criado_em timestamptz NOT NULL DEFAULT now()
);

-- só o serviço de aprovação grava aqui, sempre com o comando assinado (Ed25519)
CREATE TABLE comandos (
  cmd_id uuid PRIMARY KEY,
  espaco text NOT NULL,
  dispositivo text NOT NULL,
  acao text NOT NULL,
  impacto text NOT NULL,
  pedido_por text NOT NULL,
  aprovado_por text,
  assinado jsonb NOT NULL,
  status text NOT NULL DEFAULT 'pendente',
  motivo_ack text,
  criado_em timestamptz NOT NULL DEFAULT now(),
  ack_em timestamptz
);

CREATE TABLE auditoria (
  id bigserial PRIMARY KEY,
  ts timestamptz NOT NULL DEFAULT now(),
  ator text NOT NULL,
  acao text NOT NULL,
  detalhe jsonb
);

-- visão usada pelo painel: últimas leituras por dispositivo
CREATE VIEW ultimas_leituras AS
  SELECT DISTINCT ON (dispositivo) dispositivo, espaco, ts, payload
  FROM telemetria WHERE tipo IN ('telemetry','state') ORDER BY dispositivo, ts DESC;
CREATE VIEW eventos AS
  SELECT ts, espaco, dispositivo, payload->>'event' AS evento, payload->>'sev' AS sev, payload->'data' AS dados
  FROM telemetria WHERE tipo = 'event';
