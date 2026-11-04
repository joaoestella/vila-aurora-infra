# Estimativa de custos e plano de manutenção (RT-20)

Valores aproximados, em reais, para a Rede Vila Aurora (5 espaços). Ordem de grandeza para decisão, não cotação.

## Implantação (uma vez)
| Item | Qtd | Unit. | Total |
|---|---|---|---|
| Nó de borda (Raspberry Pi 4 + cartão + fonte) | 5 | 650 | 3.250 |
| Sensores/atuadores por espaço (kit) | 5 | 500 | 2.500 |
| Modem 4G de reserva + chip | 5 | 300 | 1.500 |
| Switch/VLAN simples por espaço | 5 | 180 | 900 |
| Mão de obra de instalação (voluntária + 1 técnico) | — | — | 1.500 |
| **Subtotal implantação** | | | **9.650** |

## Operação (12 meses)
| Item | Mensal | Ano |
|---|---|---|
| VM na nuvem (2 vCPU/4 GB) para ingestão, painel, SIEM leve | 120 | 1.440 |
| Planos 4G de reserva (5 chips, franquia baixa) | 150 | 1.800 |
| Domínio + e-mail transacional (SPF/DKIM/DMARC) | 25 | 300 |
| Energia extra dos nós (desprezível, ~5 W cada) | 10 | 120 |
| Manutenção/contingência | 100 | 1.200 |
| **Subtotal operação/ano** | | **4.860** |

O consumo medido do nó de borda (ver métricas) foi de ~1% de CPU e ~56 MB de RAM, o que cabe folgado num
Raspberry Pi e mantém o custo de energia desprezível. O SIEM leve próprio evita o custo de 8 GB do Wazuh.

## Plano de manutenção
| Tarefa | Frequência | Responsável |
|---|---|---|
| Atualização de firmware dos dispositivos (OTA **assinado**) | trimestral ou sob CVE | técnico voluntário |
| Renovação de certificados de dispositivo (validade 90 dias, rotação automatizada) | automática + conferência mensal | coordenação técnica |
| Renovação da CA emissora | anual | coordenação técnica |
| Backup do banco e das configs (cifrado) | semanal | voluntário de TI |
| Revisão de regras do SIEM e dos playbooks do SOAR | trimestral | responsável de segurança |
| Exercício de phishing + conscientização | trimestral | coordenação |
| Teste de caos (queda de link) | semestral | equipe |
