# Projeto e entregas

O projeto investiga o custo operacional e de compatibilidade da migração gradual de integrações financeiras REST/JSON e SOAP/XML para criptografia pós-quântica. O [README](../README.md) contém a questão de pesquisa, o exemplo da boleta, o escopo do MVP e o plano de cinco semanas.

## Estado do projeto

- **Sprint 1:** contratos REST e SOAP, modelos de boleta, estados e mensagens, vetores canônicos e assinados e provas isoladas de assinaturas e TLS. O [índice da sprint](../docs/sprint-1/README.md) identifica a revisão verificada, as evidências e os limites. O [plano da Sprint 1](../docs/SPRINT-1.md) é histórico, não um backlog para as próximas sprints.
- **MVP planejado:** fluxo ponta a ponta com gestora simulada, custodiante REST e administrador SOAP, persistência, recuperação e conciliação. As etapas seguintes incluem as configurações C1–C6, migração de política, rotação de chaves e avaliação experimental. Consulte a [sequência de implementação](../SPEC.md#9-organização-e-sequência-de-implementação) antes de propor trabalho de uma etapa posterior.

As provas isoladas não demonstram serviços funcionais, interoperabilidade de conectores, migração sob carga ou desempenho do fluxo integrado. O estado de cada entrega deve ser confirmado na documentação e nas evidências da revisão correspondente.
