-- Privilégio mínimo: cada serviço tem o próprio usuário com só o que precisa.
\connect vila
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO ingest_app, panel_app, approval_app, auditor_ro;

GRANT SELECT, INSERT ON telemetria, acessos TO ingest_app;
GRANT USAGE ON SEQUENCE telemetria_id_seq, acessos_id_seq TO ingest_app;
GRANT SELECT, UPDATE (status, motivo_ack, ack_em) ON comandos TO ingest_app;

-- o painel só lê; não grava comando, não lê hash de senha de ninguém além do login
GRANT SELECT ON ultimas_leituras, eventos, acessos TO panel_app;
GRANT SELECT (id, login, nome_exibicao, perfil, senha_hash, totp_secret, ativo, falhas, bloqueado_ate) ON operadores TO panel_app;
GRANT UPDATE (falhas, bloqueado_ate) ON operadores TO panel_app;
GRANT SELECT (cmd_id, espaco, dispositivo, acao, impacto, pedido_por, aprovado_por, status, motivo_ack, criado_em, ack_em) ON comandos TO panel_app;
GRANT SELECT ON aprovacoes TO panel_app;
GRANT INSERT ON auditoria TO panel_app;
GRANT USAGE ON SEQUENCE auditoria_id_seq TO panel_app;

GRANT SELECT, INSERT, UPDATE ON aprovacoes TO approval_app;
GRANT USAGE ON SEQUENCE aprovacoes_id_seq, auditoria_id_seq TO approval_app;
GRANT SELECT, INSERT ON comandos TO approval_app;
GRANT INSERT, SELECT ON auditoria TO approval_app;

GRANT SELECT ON auditoria, acessos, eventos TO auditor_ro;
