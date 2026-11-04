# Roteiro do vídeo de demonstração (até ~8 a 10 min)

Objetivo: mostrar o ambiente reproduzível pelo README e uma demonstração real, não só slides.

1. Abertura (30s). Quem somos, a Rede Vila Aurora e o incidente INC-VA-0712 em uma frase. Mostrar a Figura 1 (arquitetura).
2. Subir o ambiente (1min). Rodar `make pki` e `make up` e abrir o painel em https://localhost:8443 e a página local da borda em http://localhost:8080.
3. Operação normal e acessibilidade (1min). Logar no painel com senha + MFA, mostrar os perfis (RBAC) e a navegação por teclado.
4. SQL Injection antes e depois (1min30). No painel legado, rodar o payload UNION e mostrar a versão/esquema do banco e o erro vazando. No painel novo, o mesmo payload volta HTTP 400. Mostrar o sqlmap confirmando os dois lados.
5. Resiliência, teste de caos (1min30). Derrubar o link (`make caos MIN=30`, acelerar no vídeo), mostrar a página local funcionando, o buffer enchendo e, ao voltar, a reconciliação sem perda.
6. Câmara fria sem internet (1min). Injetar o cenário de excursão de temperatura e mostrar a sirene disparando pela regra local, com a internet caída.
7. Detecção e resposta (1min). Forçar um login de VPN anômalo e uma injeção, mostrar os 4 alertas no SIEM e o SOAR bloqueando o IP e encerrando a sessão; mostrar o comando forjado recusado pela borda.
8. IA (45s). Rodar `make ia` e mostrar as métricas do Isolation Forest e os guardrails de LLM bloqueando o prompt injection.
9. Forense (45s). Rodar a reprodução do incidente e mostrar a cadeia de custódia com hashes e a linha do tempo.
10. Fechamento (30s). Custos, privacidade e a frase final: cada falha do incidente tem hoje um controle.

Dica: todos têm que conseguir explicar qualquer parte. Dividir as seções entre os três integrantes.
