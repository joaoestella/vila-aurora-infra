# Atalhos do laboratório Rede Vila Aurora
SHELL := /bin/bash
.PHONY: pki up incidente todos down limpar seed caos ia phishing dkim testes
pki:            ## Gera a CA, os certificados e a malha WireGuard + DKIM
	PKI_OUT="$$PWD/certs-src" bash pki/bootstrap.sh
	PKI_OUT="$$PWD/certs-src" bash pki/deploy.sh "$$PWD/certs"
	python3 -c "import sys;sys.path.insert(0,'common');import cmdsig;import os;os.makedirs('keys',exist_ok=True);cmdsig.new_keypair('keys/cmd-signer.key','keys/cmd-signer.pub')"
	mkdir -p secrets && head -c 32 /dev/urandom > secrets/pseudo.key
	bash vpn/gerar_wireguard.sh && bash phishing/gerar_dkim.sh
up:             ## Sobe a nuvem + o espaço UBS
	docker compose up -d --build
incidente:      ## Sobe também o painel legado vulnerável (para reproduzir o INC-VA-0712)
	docker compose --profile incidente up -d --build
down:           ## Para tudo
	docker compose --profile incidente --profile todos down
limpar:         ## Para e apaga volumes (recomeça do zero)
	docker compose --profile incidente --profile todos down -v
seed:           ## Popula o banco com dados sintéticos e cria os operadores
	docker compose exec -T db bash -lc 'echo ok' ; python3 cloud/db/seed.py
caos:           ## Teste de caos (padrão 30 min). Ex.: make caos MIN=30
	CHAOS_MIN=$${MIN:-30} python3 caos/chaos_test.py --edge http://localhost:8080
ia:             ## Avalia o Isolation Forest e os guardrails de LLM
	python3 ai/anomalias.py --eval ; python3 ai/llm_guard.py
testes:         ## Testes automatizados (SQLi, mTLS, assinatura de comando, guardrails)
	python3 -m pytest -q tests
