# SIEM com Wazuh (opcional, para quem tem ~8 GB livres)

O enunciado sugere o Wazuh. Ele consome bastante memória, então o projeto traz **duas rotas equivalentes**:

- **Coletor próprio** (`siem/detector.py`): leve, roda em qualquer máquina, aplica as mesmas 4 regras. É o padrão do `docker-compose.yml`.
- **Wazuh**: para quem tem recurso. Os arquivos deste diretório plugam os mesmos logs JSON no Wazuh e reproduzem as 4 regras como `rules` do Wazuh.

Como os dois lêem os **mesmos campos de log** (contrato em `common/vlog.py`), as regras são equivalentes e o laudo forense não muda.

## Subir o Wazuh
```
docker compose -f siem/wazuh/docker-compose.wazuh.yml up -d
```
Depois aponte o agente/`localfile` para `/var/log/vila/*.log` (volume `logs`) e carregue `local_rules.xml` e `local_decoders.xml`.
