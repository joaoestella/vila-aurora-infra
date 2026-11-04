# Rede Comunitária Vila Aurora — infraestrutura segura e resiliente

Protótipo da GS 2026.2 de Cybersecurity (FIAP). Uma plataforma em camadas (campo, borda, nuvem, supervisão)
para a rede comunitária fictícia de Serra Clara, que **continua operando quando a internet cai** e que foi
projetada a partir das falhas do incidente **INC-VA-0712** — cada falha tem um controle correspondente.

> Tudo aqui usa **dados sintéticos** e roda em **ambiente isolado**. Nenhuma atividade ofensiva fora deste laboratório.

## O que está incluído (mapa dos requisitos)

| Requisito | Onde |
|---|---|
| RT-01/02/03 Arquitetura em camadas, operação local, redundância | `edge/edge_agent.py`, `docs/arquitetura.png` |
| RT-04/05 Identidade X.509 por dispositivo, mTLS, revogação (CRL) | `pki/`, `cloud/pkiapi/`, brokers com `require_certificate` |
| RT-06/07 VPN WireGuard + MFA, segmentação, menor privilégio | `vpn/`, `nftables.conf` |
| RT-08 SQL Injection: exploração e correção | `cloud/panel_legado/` (vulnerável) × `cloud/panel/` (corrigido), `evidencias/sqli_*` |
| RT-09 MFA + RBAC (operador/técnico/coordenação/auditor) | `cloud/panel/app.py` |
| RT-10/11/18 SPF/DKIM/DMARC, phishing simulado, ameaças por IA | `phishing/`, `dns/` |
| RT-12/13 Logs centralizados (NTP) + SIEM + 4 regras | `siem/` (coletor próprio e Wazuh) |
| RT-14 Forense do INC-VA-0712 (hash, custódia, timeline, ATT&CK) | `forense/`, `evidencias/` |
| RT-15 SOAR: respostas de baixo risco + aprovação humana | `soar/` |
| RT-16/17 IA defensiva (Isolation Forest) + guardrails de LLM | `ai/` |
| RT-19 Privacidade/LGPD, pseudonimização, RIPD | `docs/RIPD.md`, pseudonimização na borda |
| RT-20 Custos e manutenção | `docs/custos_manutencao.md` |
| RT-21 Painel acessível (WCAG 2.1 AA) | `cloud/panel/app.py` |
| RT-22/23 Métricas e teste de caos (≥30 min) | `caos/`, `evidencias/` |
| Diferenciais: firmware assinado, STRIDE, IaC (compose) | `toolbox/assinar_firmware.py`, `docs/`, `docker-compose.yml` |

## Como rodar (passo a passo)

Pré-requisitos: Docker + Docker Compose, Python 3.12, OpenSSL, `wireguard-tools`.

```bash
cp .env.exemplo .env           # troque TODAS as senhas
make pki                       # gera CA, certificados por dispositivo, WireGuard e DKIM
python3 cloud/db/seed.py       # (ou deixe o compose popular) dados sintéticos + operadores
make up                        # sobe nuvem + espaço UBS
#   painel de supervisão:  https://localhost:8443
#   página local da borda: http://localhost:8080  (funciona mesmo com a nuvem fora)
```

### Caminho recomendado no Windows: WSL, sem Docker (validado)
```bash
sudo apt update && sudo apt install -y python3-pip python3-venv openssl wireguard-tools postgresql mosquitto make git
python3 -m venv ~/venv-vila && source ~/venv-vila/bin/activate
pip install flask paho-mqtt psycopg2-binary pyotp scikit-learn numpy pandas cryptography dkimpy requests pytest sqlmap psutil
make pki                       # certificados, WireGuard, DKIM (uma vez)
bash scripts/lab.sh up         # sobe banco, nuvem, SIEM, SOAR, borda e dispositivos
bash scripts/lab.sh sqli       # SQL Injection: legado x corrigido
bash scripts/lab.sh incidente  # reproduz o INC-VA-0712, gera alertas, respostas e evidências
bash scripts/lab.sh cenario-frio   # câmara fria quente: sirene local, mesmo sem internet
bash scripts/lab.sh caos 30    # teste de caos de 30 min
bash scripts/lab.sh alertas | status | down
```
Painel corrigido em http://localhost:18000, borda em http://localhost:18080, legado em http://localhost:18081.
O `docker-compose.yml` é uma alternativa e não foi validado; o caminho acima é o testado.

Outros comandos (também funcionam no WSL):
```bash
make incidente                 # sobe também o painel legado vulnerável
python3 forense/reproduzir_incidente.py   # encena o INC-VA-0712 e coleta evidências
make ia                        # avalia Isolation Forest e guardrails de LLM
make caos MIN=30               # teste de caos de 30 min (continuidade + reconciliação)
make testes                    # testes automatizados dos controles
```

Credenciais dos operadores de laboratório ficam em `secrets/operadores-lab.txt` (gerado localmente, fora do Git).

## Estrutura
```
pki/        CA própria, emissão/revogação de certificados, deploy
edge/       nó de borda autônomo + políticas por espaço + brokers
devices/    simulador dos dispositivos de campo (MQTT mTLS)
cloud/      ingestão mTLS, painel corrigido, painel legado, PKI API, banco
soar/       serviço de aprovação (assina comandos) + SOAR (respostas)
vpn/        WireGuard + portão de acesso com MFA + segmentação
phishing/   SPF/DKIM/DMARC + campanha simulada + conscientização
siem/       coletor próprio (4 regras) e configuração do Wazuh
ai/         Isolation Forest (anomalias) e guardrails de LLM
forense/    reprodução do INC-VA-0712 + aquisição de evidências
caos/       teste de caos e métricas
toolbox/    assinatura de firmware (OTA)
evidencias/ saídas dos testes (hashes, métricas, SQLi, IA, phishing)
docs/       arquitetura, RIPD, custos, STRIDE
tests/      testes automatizados
```

## Segurança do repositório
Chaves privadas, `.env` e credenciais **não são versionados** (`.gitignore`). Rode `make pki` para gerar o seu material localmente.

## Uso de IA
Ver `docs/uso_de_ia.md`.
