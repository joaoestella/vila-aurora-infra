# RIPD simplificado — Relatório de Impacto à Proteção de Dados (RT-19, LGPD)

**Contexto:** plataforma comunitária que registra acessos a portas, telemetria de recursos (água, energia,
temperatura) e operadores do painel. Todos os dados do protótipo são **sintéticos**.

## Dados tratados e minimização
| Dado | Por que | Minimização aplicada |
|---|---|---|
| Crachá de acesso | registrar entrada/saída | **pseudonimizado na borda** (HMAC-SHA256 com chave local) antes de sair do espaço; a nuvem nunca vê o crachá em claro |
| Operadores do painel | autenticação e RBAC | só login, nome de exibição e perfil; senha com hash (pbkdf2), segredo TOTP; sem CPF/telefone |
| Telemetria de sensores | operação e alertas | dado de equipamento, não pessoal; sem vínculo a indivíduos |

## Base legal (LGPD)
- Execução de **políticas públicas**/legítimo interesse da associação para segurança dos espaços (art. 7º).
- Consentimento específico para o exercício de phishing (apenas contas fictícias).

## Retenção
- Telemetria: 90 dias on-line, depois agregada.
- Registros de acesso (pseudonimizados): 180 dias.
- Logs de segurança/forense: 1 ano.
- Reidentificação de crachá: só a coordenação, com registro em auditoria e justificativa.

## Riscos e medidas
| Risco | Medida |
|---|---|
| Vazamento da tabela de usuários (como no incidente) | banco novo não guarda dados pessoais; privilégio mínimo; SQLi eliminado |
| Correlação de acessos → rastrear pessoas | pseudonimização + acesso restrito + retenção curta |
| Exposição de segredos no repositório | `.gitignore` + geração local de chaves |

## Direitos dos titulares
Canal da coordenação para acesso, correção e eliminação; a pseudonimização permite localizar e remover registros de um titular mediante a chave, sob controle da coordenação.
