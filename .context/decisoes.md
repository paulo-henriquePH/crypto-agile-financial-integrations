# Registros de decisão de arquitetura (ADRs)

As decisões ficam em [`docs/adr/`](../docs/adr/). A [SPEC](../SPEC.md) exige que alterações com impacto em contratos, segurança ou resultados experimentais atualizem a especificação e registrem a justificativa em uma ADR. A necessidade vem do impacto da decisão, não do calendário da sprint.

## Como registrar

1. Consulte as decisões existentes. Complemente a ADR em vigor quando estiver preenchendo uma etapa já prevista; se uma nova decisão substituir a anterior, crie outra ADR e vincule as duas para preservar o histórico.
2. Para uma nova ADR, use `NNNN-assunto.md`, com o próximo número disponível. Registre status, data, contexto, alternativas, decisão e consequências. Vincule os requisitos afetados, as evidências e os comandos de reprodução, quando aplicáveis.
3. Distinga propostas, resultados de laboratório e decisões validadas para os serviços. Declare limitações e pendências; não conclua que um componente está aprovado apenas pela presença de uma API ou pela versão de uma biblioteca.

## Próxima decisão de stack

A [ADR 0001](../docs/adr/0001-stack.md) registra a referência de laboratório, não a aprovação da stack dos serviços. Antes de implementar os serviços, cumpra o [gate de stack](../SPEC.md#2-arquitetura-e-execução): demonstre assinatura e verificação com os dois algoritmos, canonicalização interoperável no runtime escolhido e controle dos grupos TLS nos clientes e servidores candidatos. Complemente a ADR 0001 com linguagem, runtime, frameworks, clientes, servidores e bibliotecas escolhidos, suas versões, o método de observação do grupo negociado e os comandos e evidências das provas. Se a terminação TLS mudar a fronteira de confiança, atualize também o [modelo de ameaças](../docs/security/threat-model.md).
