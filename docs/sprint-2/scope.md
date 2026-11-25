# Sprint 2 — baseline e aceite do fluxo C1

**Revisão de partida:** `3fedb5f8b2fb959db277d9a34fc0e2770adddfcc`, branch `sprint-2-c1`. Na abertura de S2-01, `README.md` estava modificado e o plano `docs/SPRINT-2.md` ainda não era rastreado. O recorte segue a [semana 2 do README](../../README.md#plano-de-desenvolvimento) e o plano disponível no checkout de trabalho. A matriz abaixo define verificações futuras; nenhum cenário C1 está aprovado nesta revisão.

## O que entra da Sprint 1

A [baseline congelada](../sprint-1/README.md#congelamento-e-compatibilidade) corresponde ao commit `d715c2c2980b34ddab6fe62322a6f5f569e669b1`. A [evidência final](../sprint-1/evidence/final-verification.json) registra checkout limpo, saída 0 e zero skips: contratos, bytes canônicos, vetores estáticos e recém-assinados nos três perfis e os dois grupos TLS observados no harness. A [ADR 0001](../adr/0001-stack.md) estabelece CPython 3.13.11, `ctypes` e OpenSSL 3.5.9 como referência de laboratório. O ACK do harness não trafegou por REST ou SOAP; a carga offline do WSDL não chamou um serviço.

| Referência congelada | Uso no fluxo |
|---|---|
| [Schemas](../../contracts/schemas/), [transições](../../contracts/domain/) e [fixtures](../../fixtures/) | Boleta imutável, versão 1, decimais exatos e sequência de eventos. |
| [OpenAPI da plataforma](../../contracts/openapi/platform.yaml) e [do custodiante](../../contracts/openapi/custodian.yaml) | Criação e consulta pela gestora; instrução e consulta de custódia. |
| [WSDL do administrador](../../contracts/soap/administrator.wsdl), [XSD do administrador](../../contracts/soap/administrator.xsd) e [XSD do envelope](../../contracts/soap/envelope.xsd) | SOAP 1.2: `RegisterOperation`, `GetOperation`, confirmações e erros assinados. |
| [Mensagens](../../contracts/messages/), [JCS](../../contracts/vectors/json/), [C14N](../../contracts/vectors/xml/) e [corpus assinado](../../contracts/vectors/signed/) | Conferir contexto, bytes e assinaturas reais; as assinaturas dos exemplos estruturais são ilustrativas. |

Incompatibilidade com esses contratos bloqueia a task. Uma quebra exige versão e migração explícitas, vetores atualizados e repetição das verificações afetadas e da integração, conforme a [SPEC §4](../../SPEC.md#4-contratos-de-integração).

## Matriz de aceite C1

O cenário usa apenas dados sintéticos. Gestora → plataforma e plataforma → custodiante usam REST/JSON; plataforma → administrador usa SOAP/XML. Em C1, cada enlace exige mTLS 1.3 com X25519 e autenticação tradicional; cada mensagem de negócio exige ECDSA P-256/SHA-256. A plataforma assina com sua própria identidade e preserva `managerId`. A configuração inicial por integração é versionada, com chaves previamente registradas.

As linhas desdobram a tabela “Critérios de encerramento da sprint” de `docs/SPRINT-2.md`. Os IDs T remetem à [SPEC §8](../../SPEC.md#8-verificação-e-critérios-de-entrega); indicam o recorte a testar, não resultados.

| Requisito da semana 2 / SPEC | Tasks | Como verificar o aceite |
|---|---|---|
| Gate da stack (§2; parcela de T14) | S2-02, S2-03 | No runtime candidato, assinar/verificar ECDSA DER e ML-DSA-65 puro sem subprocesso por assinatura; comparar JCS e Exclusive C14N 1.0 sem comentários aos bytes congelados e entregar ao negócio o mesmo nó XML verificado. Nos três enlaces candidatos em processos separados, trocar mensagens reais com mTLS e observar **nas duas pontas** X25519 e X25519MLKEM768 em conexões distintas, cadeia/nome, identidade ligada à política e falha sem fallback. Registrar escolhas, versões, comandos e observação na ADR antes de S2-04. |
| Persistência (§§2–3) | S2-04, S2-06, S2-07, S2-11 | Subir Compose/Linux e PostgreSQL de laboratório a partir de base vazia. Conferir isolamento por base/credencial entre os três serviços, sobrevivência ao reinício e unicidade transacional de eventos, intenções na outbox e efeitos deduplicados na inbox dos destinatários. |
| Proteção, autorização e parsers (§5; T05 em C1, T07, T08) | S2-03, S2-05, S2-06, S2-07, S2-11, S2-14 | No fluxo observar versão TLS, grupo X25519, suíte e autenticação em cada enlace; verificar envelopes de pedido, resposta e erro. Recusar certificado inválido, grupo incompatível, `senderId`, carteira ou ação não autorizados, adulteração, expiração, chave, ambiente ou destinatário incorretos, JSON duplicado e XML ambíguo ou com entidades, sem resolução externa, fallback ou efeito financeiro. |
| Registro, envio e consultas de status (T01; §§3–4) | S2-06, S2-07, S2-08, S2-09, S2-14 | Criar boleta válida pela API (`201`, UUID); conferir outbox atômica e `SENT` persistido antes do envio. `202` comprova apenas `RECEIVED`. Com consultas assinadas de novo `messageId`, seguir o mesmo UUID por `ACCEPTED`, `PENDING_SETTLEMENT` e `SETTLED`; avançar relógio financeiro pelo runner e contar exatamente um débito e um crédito. |
| Rejeição e falha de liquidação (T01; §6) | S2-06, S2-08, S2-09, S2-14 | Financeiro inconsistente: `REJECTED` local com motivo, sem envio. Rejeição operacional: motivo do custodiante visível na plataforma, sem lançamentos. Saldo insuficiente: `SETTLEMENT_FAILED` sem efeito parcial. |
| Registro SOAP e conciliação (§§4, 6; T01, T12) | S2-11, S2-12, S2-13, S2-14 | Após terminal no custodiante, registrar e consultar o snapshot independente no administrador. Comparar os três registros por UUID/versão, usando os campos da §6. Confirmar um registro SOAP e `MATCHED` na consulta da plataforma; introduzir divergência controlada no administrador e conferir `DIVERGENT`, campo e valores por origem, mantendo `SETTLED`. |
| Reenvio, concorrência e conflito (T02, T09) | S2-06, S2-07, S2-08, S2-11, S2-12, S2-14 | Duas criações simultâneas para `(managerId, clientOrderId)` produzem um UUID. Replay e reemissão válida dos comandos recuperam o resultado sem multiplicar operação, lançamentos ou registro SOAP. Negócio alterado na mesma identidade lógica gera conflito; mesmo `messageId` com bytes diferentes também é recusado. Verificar validade e autorização antes de devolver resultado anterior. |
| Timeout, indisponibilidade e reinício (T03, T04, T13) | S2-10, S2-12, S2-14 | Perder resposta após commit e reiniciar o worker: consultar antes de retransmitir; só `NOT_FOUND` assinado e correlacionado permite novo envio. Consulta inconclusiva mantém `UNKNOWN`; limite esgotado deixa `BLOCKED` persistido. Administrador indisponível deixa conciliação `NOT_READY`; retomar da outbox sem duplicidade nem mudança da liquidação. |
| Ordem e lacunas no histórico (T12) | S2-09, S2-10, S2-13, S2-14 | Reaplicar evento antigo/duplicado sem regressão; diante de lacuna, consultar a sequência remota. Só avançar a projeção se os eventos faltantes forem recuperados e verificados. |
| Demonstração e reprodução (§§7–8) | S2-14, S2-15 | Em checkout limpo, executar um verificador que registra, envia, acompanha e concilia via APIs, com banco, TLS e assinaturas reais. Relatório sanitizado por cenário: revisão, versões, parâmetros, operação, mensagem, correlação, política, tentativa, `keyId`, mecanismos observados, resultado e saída. Falha, skip obrigatório ou mecanismo diferente de C1 deve resultar em saída não zero. |

## Passagem às etapas seguintes

O gate S2-02/S2-03 é pré-requisito para implementar os serviços, não aceite do fluxo financeiro. A **semana 3** levará ML-DSA, perfil duplo e TLS híbrido aos dois adaptadores, com políticas por integração, instrumentação e execução das seis configurações (T06, ampliação de T05 e conclusão de T14). A **semana 4** responde pela ativação de políticas, rotação, migração sob carga, T10/T11 e piloto. A **semana 5** responde pela coleta definitiva e análise comparativa. A aprovação de C1 isoladamente não encerra o MVP.
