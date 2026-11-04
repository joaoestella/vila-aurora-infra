# Modelagem de ameaças STRIDE com rastreabilidade até os controles (diferencial)

| Categoria | Ameaça no cenário | Controle | Requisito |
|---|---|---|---|
| **S**poofing | dispositivo falso publica telemetria; operador falso acessa | certificado X.509 por dispositivo (mTLS), MFA nos operadores | RT-04, RT-09 |
| **T**ampering | alterar agendamento da bomba (como no incidente); adulterar firmware | comando assinado (Ed25519) verificado na borda; firmware OTA assinado | RT-15, diferencial |
| **R**epudiation | negar ter emitido um comando/decisão | auditoria + cadeia de custódia + logs assinados no tempo (NTP) | RT-12, RT-14 |
| **I**nformation disclosure | SQLi exfiltra tabela de usuários; crachá exposto | consultas parametrizadas + privilégio mínimo; pseudonimização | RT-08, RT-19 |
| **D**enial of service | queda da fibra deixa a UBS sem alarme | operação local autônoma + buffer + 4G de reserva | RT-02, RT-03 |
| **E**levation of privilege | sessão VPN sem MFA vira acesso total ao painel | ZTNA/VPN + MFA + segmentação + RBAC; nenhuma porta admin exposta | RT-06, RT-07 |

Cada controle acima está implementado no protótipo e referenciado no relatório técnico.
