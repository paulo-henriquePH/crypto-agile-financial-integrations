# Baseline e escopo da Sprint 1

Data da baseline: 2026-11-19. Fontes: [README](../../README.md), [SPEC v0.1](../../SPEC.md) e [plano da Sprint 1](../SPRINT-1.md). A SPEC define o MVP; o plano delimita a entrega desta sprint. Os caminhos de artefatos abaixo são destinos planejados, não declarações de implementação ou de testes aprovados.

## Resultado esperado e rastreabilidade

A sprint entrega contratos verificáveis e provas isoladas de viabilidade. A escolha da stack depende da execução real das primitivas e dos handshakes, observada pelo runtime candidato. Canonicalização e contratos também precisam ser verificados antes dos conectores. Nenhum suporte é presumido a partir da versão de uma biblioteca.

| Task | Requisito e origem | Artefato previsto | Verificação necessária |
|---|---|---|---|
| S1-01 | Baseline e limites; README, plano e SPEC | `SPEC.md`, `docs/SPRINT-1.md`, este documento | Revisão cruzada dos requisitos, referências e itens adiados; preservar arquivos preexistentes. |
| S1-02 | Ameaças, identidade e confiança; SPEC §§4–5 | `docs/security/threat-model.md` | Ativos, atores, fronteiras, ataques, controles, riscos residuais e vínculo a testes presentes ou futuros. |
| S1-03 | Ambiente Linux reproduzível; SPEC §2 | `deploy/spikes/`, `spikes/README.md`, manifesto | Dependências fixadas e verificadas em fontes oficiais, ambiente limpo, runtime e bindings carregados, segredos excluídos do Git. Inventário não equivale a execução criptográfica. |
| S1-04 | ECDSA P-256/SHA-256 em DER; SPEC §5 | `spikes/signatures/ecdsa/`, evidência sanitizada | Assinar/verificar pelo runtime, sem subprocesso por assinatura; rejeitar payload, assinatura e chave alterados. |
| S1-05 | ML-DSA-65 puro; SPEC §5 | `spikes/signatures/ml-dsa/`, evidência sanitizada | Mensagem completa, contexto vazio, casos positivos/negativos, tamanhos brutos e codificados, comparação normativa. |
| S1-06 | TLS 1.3 e X25519; SPEC §5 | `spikes/tls/`, gerador de CA/certificados, evidência | Handshake real com mTLS; grupo observado, suíte e identidade; sem retomada/0-RTT; cadeia não confiável e nome incorreto falham. |
| S1-07 | TLS 1.3 e X25519MLKEM768; SPEC §5 | Mesmo harness TLS e evidência híbrida | Grupo híbrido efetivo, conexão/processo novos, suíte e autenticação controladas; cliente apenas X25519 falha sem fallback. |
| S1-08 | Decisão fundamentada da stack; SPEC §2 | `docs/adr/0001-stack.md` | Matriz de suporte vinculada às provas S1-03–07, APIs versus CLI, terminação TLS e limitações; impedimentos exigem correção. |
| S1-09 | Boleta e regras financeiras; SPEC §3 | `contracts/schemas/`, `fixtures/boletas/`, `tests/contracts/` | Tipos, enums, escalas, limites, cadastros, imutabilidade, quantidade × PU, HALF_UP, overflow, datas e negativos. Separar `clientOrderId` de UUID `operationId`. |
| S1-10 | Estados e eventos; SPEC §3 | `contracts/domain/`, schema e sequências | Estado inicial, terminais e origem da rejeição; transição inválida, regressão, repetição e lacuna; documentar recuperação por consulta. |
| S1-11 | Envelope e perfis; SPEC §§4–5 | `contracts/messages/`, schemas e exemplos | Contexto, correlação, validade, política, identidade lógica versus mensagem, criação sem UUID, respostas/erros assinados e signatários vinculados ao conteúdo. Duplo exige ambas. |
| S1-12 | JCS; SPEC §5 | `contracts/vectors/json/` e executor | Bytes UTF-8 de `{protected, payload}`, decimais string, duplicatas rejeitadas, Unicode/escapes/tipos; expectativas independentes e digest. |
| S1-13 | Exclusive C14N sem comentários; SPEC §5 | XSD comum e `contracts/vectors/xml/` | Um único nó `SignedContent` no caminho previsto, mesmo nó verificado/processado, DTD/entidades externas rejeitados, namespaces/atributos/whitespace e expectativas independentes. |
| S1-14 | REST da plataforma; SPEC §4 | `contracts/openapi/platform.yaml` e exemplos | Criação e consulta, mTLS/correlação, `201`, repetição, conflito, ausência, rejeição local identificada; OpenAPI, referências e exemplos validados. |
| S1-15 | REST do custodiante; SPEC §4 | `contracts/openapi/custodian.yaml` e exemplos | `202` é recibo persistido; consulta com snapshot/sequência, ausência assinada, identidade lógica e caminho/contexto; sequência timeout → consulta validada. |
| S1-16 | SOAP 1.2 do administrador; SPEC §4 | `contracts/soap/administrator.wsdl`, XSDs e exemplos | `RegisterOperation`, `GetOperation`, respostas/Faults, ações, correlação, segurança e mapeamento JSON/XML sem perda; imports locais, validação XSD e carregamento pelo cliente candidato. |
| S1-17 | Vetores assinados; SPEC §5 e parcela de T14 | `contracts/vectors/signed/` e gerador | JSON/XML, requisição/resposta/erro, ECDSA/ML-DSA/duplo; adulteração, remoção e chave trocada rejeitadas; relógio de referência; apenas chaves públicas versionadas. |
| S1-18 | Verificação reproduzível; SPEC §§8–9 | `scripts/verify-sprint1/`, relatório por caso | Um comando em ambiente limpo executa modelos, contratos, vetores e provas reais; código de saída não zero sob perturbação temporária revertida; manifesto com versões e revisão. |
| S1-19 | Entrega e congelamento; README semana 1, SPEC §9 | `docs/sprint-1/README.md`, índice/matriz, atualização do README | Revisão independente, reexecução sobre hash S1-18, limitações e reprodução; consolidação documental apenas, sem declarar funcionalidades futuras disponíveis. |

## Invariantes preservados

Recebimento, aceitação e liquidação são eventos distintos. Estado financeiro, entrega e conciliação permanecem independentes: timeout não rejeita financeiramente, divergência não desfaz liquidação. A boleta é imutável e `instructionVersion` aceita somente 1 no MVP. O identificador de mensagem é distinto do identificador de operação; consultas novas devem representar leituras novas.

A plataforma é fronteira explícita de confiança: assina como plataforma, preservando a identidade da gestora no payload. TLS híbrido protege o estabelecimento de chaves, mas a autenticação TLS continua tradicional; ML-DSA protege a autenticidade da mensagem. Não substituir algoritmo, usar mock para declarar viabilidade nem reduzir a proteção em incompatibilidades. Privadas, senhas e volumes não entram no Git.

Os contratos devem preservar as restrições da SPEC: campos desconhecidos/duplicados rejeitados, versões e tipos suportados explícitos, decimais exatos, autorização de referências, validade de até 120 s e tolerância de 5 s, limite de 256 KiB e profundidade 32. A aplicação futura continuará responsável por aplicar esses controles antes de efeitos de negócio; provas isoladas não demonstram essa integração.

## Trabalho adiado e exclusões

| Trabalho | Destino previsto | O que a sprint 1 fornece |
|---|---|---|
| APIs e simuladores financeiros executáveis, banco PostgreSQL, transações, outbox/inbox, workers e histórico persistido | Etapa 2 da SPEC / semana 2 do README | Contratos e validadores isolados, sem serviço financeiro ou migrações de banco. |
| Efeito financeiro único, concorrência/idempotência persistida, retomada após falhas e indisponibilidade do administrador | Etapa 2 | Identidades, estados e semântica de recuperação; não prova operacional de T02–T04, T09 e T13. |
| Liquidação, caixa/posição, conciliação entre participantes e cenários completos | Etapa 2 | Modelo e snapshots contratuais; sem simulação operacional ou comparação persistida. |
| Seis configurações C1–C6 nos conectores e instrumentação integrada | Etapa 3 / semana 3 | Primitivas, dois handshakes e vetores do perfil duplo isolados. |
| Migração sob carga, rotação, revogação em trânsito, pools e plano de controle administrativo | Etapa 4 / semana 4 | Ameaças, regras contratuais e falha sem fallback; T10–T11 permanecem futuros. |
| Piloto, benchmarks completos, redes emuladas, coleta estatística e relatório de desempenho | Etapas 4–5 / semanas 4–5 | Evidências funcionais sanitizadas e manifesto das provas; sem promessa de desempenho. |

T01, T05–T08, T12 e T14 têm parcelas isoladas cobertas por domínio, contratos, segurança e criptografia nesta sprint; a aprovação integral de T01–T14 e das seis configurações pertence à liberação do MVP. CI nesta sprint depende do suporte integral do runner; a reprodução local é obrigatória e dependência ausente nunca conta como teste aprovado.

Continuam fora do MVP: instituições e infraestrutura reais, movimentação financeira real, negociação com contraparte, cálculo de PU pela taxa, HSM, interface gráfica, notificações externas assíncronas e autenticação TLS pós-quântica. Comprometimento do host e proteção física das chaves são limitações a explicitar no modelo de ameaças, sem prometer solução nesta sprint.

## Registro da baseline S1-01

Inspeção inicial: branch `develop`, commit `798eb819486c8a451cf6ab7d4f13a78ad519f38e`. `git status --short` identificou somente `SPEC.md` e `docs/SPRINT-1.md` como arquivos preexistentes não rastreados. Seus conteúdos foram preservados. A inclusão desses dois arquivos é explicitamente requerida pela S1-01; não autoriza inclusão automática de outras mudanças.

A revisão cruzada relacionou as entregas da semana 1 do README, as seções aplicáveis da SPEC e os 19 itens do plano à tabela acima. Os três links locais de origem resolvem para arquivos existentes. Esta task documental não executa provas criptográficas nem escolhe a stack. O coordenador deve submeter a alteração à revisão independente, adicionar explicitamente os três arquivos e criar o commit `docs(sprint1): registra especificacao e escopo da sprint` após aprovação. As próximas tasks continuam sequenciais, com evidência e revisão no próprio commit; correções posteriores recebem task e commit próprios.
