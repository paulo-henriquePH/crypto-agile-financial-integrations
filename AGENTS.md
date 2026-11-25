# Instruções para agentes

Este repositório contém o projeto acadêmico **Crypto-Agile Financial Integrations**. O [README](README.md) apresenta o projeto e a metodologia experimental; a [SPEC](SPEC.md) define os requisitos técnicos e os critérios de entrega.

## Contexto por tarefa

Leia os arquivos de contexto pertinentes antes de propor ou executar uma mudança. Eles indicam as fontes do projeto; não substituem a SPEC, os contratos, as ADRs ou as evidências.

| Assunto | Contexto |
|---|---|
| Objetivo, entregas comprovadas e próximos marcos | [Projeto](.context/projeto.md) |
| Domínio, contratos REST/SOAP e segurança | [Arquitetura e contratos](.context/arquitetura.md) |
| Decisões técnicas e validação da stack | [ADRs](.context/decisoes.md) |
| Testes, reprodução e critérios de entrega | [Verificação e evidências](.context/verificacao.md) |

## Regras de trabalho

- Limite a mudança à tarefa solicitada. Preserve alterações existentes e a separação entre o que foi demonstrado na Sprint 1 e o que está previsto para o MVP.
- Se uma alteração afetar contratos, segurança ou resultados experimentais, atualize a SPEC e registre a justificativa em uma ADR em `docs/adr/`, conforme o [fluxo de decisões](.context/decisoes.md). Não crie uma ADR apenas porque começou uma nova sprint.
- Não substitua silenciosamente a baseline de contratos da Sprint 1. Avalie a compatibilidade e, se houver quebra, explicite a versão e a migração, atualize os vetores e repita as verificações afetadas.
- Não invente resultados nem trate testes não executados ou pulados como aprovados. Na entrega, indique o que foi verificado e o que permanece pendente.
- Use apenas dados sintéticos. Não versione segredos, chaves privadas ou relatórios locais não sanitizados.
