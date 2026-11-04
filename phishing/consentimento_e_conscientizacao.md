# Phishing simulado: consentimento, ética e plano de conscientização (RT-11, RT-18)

## Regras éticas seguidas
- A campanha tem como alvo **apenas contas fictícias** criadas pela equipe (domínio `lab.vilaaurora.example`), nunca voluntários reais.
- **Nenhuma senha é armazenada**: a página de captura registra só que houve submissão e redireciona para a página educativa.
- Todo o exercício ocorre no ambiente **isolado** da equipe (Lei 12.737/2012 respeitada: nada contra terceiros, FIAP ou internet).
- Voz ou imagem sintética, se usada na demonstração, é só de integrantes que consentiram por escrito e vem **identificada como sintética**.

## Termo de consentimento (modelo, para um cenário real com pessoas)
> Eu, [nome], concordo em participar de um exercício interno de conscientização sobre phishing da Rede Vila Aurora,
> entendo que poderei receber e-mails de teste e que nenhum dado pessoal real ou senha será coletado ou divulgado.
> Assinatura: __________  Data: ____/____/____

## Ligação com o incidente (RT-18): ameaças potencializadas por IA
O INC-VA-0712 começou com um e-mail **sem erros, gerado por IA**, reforçado por um **áudio com a voz clonada** do secretário. Controles adotados:
- **Verificação fora de banda**: todo pedido urgente de acesso/senha é confirmado por um segundo canal (ligação para o número da lista impressa).
- **Palavra-código** combinada previamente para pedidos urgentes legítimos; quem pede sem a palavra é tratado como suspeito.
- **SPF/DKIM/DMARC** (política *quarantine*) reduzem a entrega de e-mails que falsificam o domínio.
- **Marca visual nos e-mails externos** e **botão Reportar** no cliente de e-mail dos voluntários.

## Plano de conscientização adaptado a voluntários (linguagem simples)
1. Conversa de 20 minutos, sem jargão, com exemplos reais do bairro.
2. Cartaz impresso: "Pressa + senha = desconfie. Ligue para confirmar."
3. Exercício prático trimestral (esta campanha), medindo **reporte** como indicador principal.
4. Canal fácil para reportar (botão ou número no grupo), celebrando quem reporta (sem expor quem clicou).
5. Cuidado redobrado com **áudios/vídeos**: combinar que decisões críticas nunca são pedidas só por mensagem de voz.
