-- Banco LEGADO, igual ao do incidente INC-VA-0712 (somente para reprodução em laboratório).
-- Falhas de propósito: usuário da aplicação dono de tudo, dados pessoais em claro, senha em MD5.
\connect vila_legado
CREATE TABLE usuarios (
  id serial PRIMARY KEY, nome text, cpf text, telefone text, email text, login text, senha_md5 text, perfil text
);
CREATE TABLE historico_acessos (
  id serial PRIMARY KEY, data_hora timestamp, espaco text, porta text, cracha text, nome text, resultado text
);
CREATE TABLE agendamento_bomba (
  id serial PRIMARY KEY, espaco text, bomba text, hora_liga int, hora_desliga int, ativo boolean
);
INSERT INTO agendamento_bomba (espaco,bomba,hora_liga,hora_desliga,ativo) VALUES ('escola','esc-bom-01',5,23,true),('horta','hrt-bom-01',5,19,true);
