# Plano de desenvolvimento da sprint 2 — fluxo tradicional completo

**Status:** planejado; este documento não registra implementação nem resultados da Sprint 2. **Base:** [semana 2 do README](../README.md#plano-de-desenvolvimento), [SPEC](../SPEC.md) e [entrega da Sprint 1](sprint-1/README.md).

**Objetivo:** um script registra uma compra sintética de debênture pela API da gestora, acompanha o envio ao custodiante REST e a liquidação simulada, e confirma o registro no administrador SOAP e a conciliação pela consulta da plataforma. O fluxo usa **C1: mTLS 1.3 com X25519 e assinatura de mensagem ECDSA P-256/SHA-256**. O aceite exige também rejeição, reenvio sem duplicidade, conflito e divergência verificável.

## Escopo e regras de execução

- **Entrada da sprint:** contratos, fixtures e vetores congelados na Sprint 1; [ADR 0001](adr/0001-stack.md) como referência de laboratório, não aprovação dos serviços. Antes de implementar C1, fechar a [validação obrigatória da stack (§2 da SPEC)](../SPEC.md#2-arquitetura-e-execução) em S2-02 e S2-03. ML-DSA-65 e X25519MLKEM768 entram nessas provas, não como perfis operacionais da Sprint 2.
- **Incluído:** serviços e banco reais de laboratório, API REST da plataforma, simuladores em processos separados com armazenamento independente, adaptadores REST/SOAP, histórico, outbox/inbox, autorização, idempotência, recuperação por consulta e conciliação. Usar Linux em contêineres, Docker Compose e PostgreSQL como referência da SPEC; sem broker.
- **Adiado:** perfis operacionais ML-DSA e duplo, TLS híbrido no fluxo de negócio, troca de políticas, rotação de chaves, migração sob carga, piloto e benchmarks. C1 usa configuração inicial versionada e chaves previamente registradas, sem plano de controle de migração.
- **Invariantes:** recebimento, aceitação e liquidação são distintos; falha técnica não é rejeição financeira; conciliação não altera a liquidação; um comando produz no máximo um efeito simulado. Não reduzir a proteção exigida para contornar incompatibilidade.
- **Compatibilidade:** implementar [OpenAPI](../contracts/openapi/), [WSDL/XSD](../contracts/soap/) e [envelopes](../contracts/messages/) de acordo com a especificação; usar os [vetores assinados](../contracts/vectors/signed/) para verificação criptográfica, não as assinaturas ilustrativas dos exemplos. Se surgir incompatibilidade, bloquear a task, avaliar a [baseline congelada](sprint-1/README.md#congelamento-e-compatibilidade) e, se aprovada uma quebra, explicitar versão e migração, atualizar vetores e repetir as verificações afetadas e a integração. Decisões que afetem contratos, segurança ou resultados experimentais seguem a [SPEC e o fluxo de ADRs](../.context/decisoes.md).

## Backlog de commits

Ordem nominal **S2-01 → S2-15**, uma task por vez. Cada task parte do commit aprovado da anterior, entrega testes e evidência do próprio recorte e passa por revisão antes do commit. Os caminhos abaixo são planejados; nomes de comandos e dependências só são fixados com a stack. Não há estimativa por task: a validação dos clientes e servidores é o primeiro risco do cronograma.

| Task | Resultado | Agente executor | Commit planejado |
|---|---|---|---|
| S2-01 | Baseline e recorte de aceite C1 | Arquitetura | `docs(sprint2): registra baseline e escopo do fluxo C1` |
| S2-02 | Provas de assinatura e canonicalização no runtime candidato | Criptografia | `test(stack): valida assinaturas e parsers candidatos` |
| S2-03 | Provas mTLS REST/SOAP e decisão da stack | Arquitetura | `test(stack): comprova transporte e fecha gate dos servicos` |
| S2-04 | Ambiente dos serviços e base de persistência | Persistência | `build(deploy): prepara ambiente e persistencia dos servicos` |
| S2-05 | Transporte, envelopes e autorização C1 | Segurança | `feat(security): integra mtls e envelopes ECDSA em C1` |
| S2-06 | Registro e consulta da gestora, com fila persistida | Plataforma | `feat(platform): registra e consulta operacoes da gestora` |
| S2-07 | API REST e recebimento idempotente no custodiante | REST/Custódia | `feat(custodian): recebe e consulta instrucoes REST` |
| S2-08 | Decisão e liquidação simulada persistidas | REST/Custódia | `feat(custodian): simula decisao e liquidacao atomica` |
| S2-09 | Envio e acompanhamento REST pela plataforma | Plataforma | `feat(platform): envia e acompanha instrucoes de custodia` |
| S2-10 | Recuperação do envio e retomada após reinício | Plataforma | `feat(platform): recupera entregas de custodia inconclusivas` |
| S2-11 | Registro e consulta no simulador SOAP | SOAP | `feat(administrator): registra e consulta operacoes por SOAP` |
| S2-12 | Atualização e leitura do administrador pela plataforma | SOAP | `feat(platform): integra registro e consulta do administrador` |
| S2-13 | Conciliação dos três registros | Domínio | `feat(reconciliation): compara e persiste resultados por operacao` |
| S2-14 | Demonstração, suíte integrada e reprodução C1 | Validação | `test(sprint2): integra demonstracao e verificacao C1` |
| S2-15 | Consolidação das evidências e instruções | Arquitetura | `docs(sprint2): consolida evidencias do fluxo C1` |

### S2-01 Registrar a baseline

- **Entrada:** README, SPEC, este plano, [índice da Sprint 1](sprint-1/README.md) e ADR 0001.
- **Entrega:** recorte de escopo e baseline em `docs/sprint-2/scope.md`, com revisão de partida, contratos de referência e matriz de aceite C1.
- **Aceite:** cada requisito da semana 2 aponta para task e verificação; nenhuma prova isolada é tratada como serviço validado; responsabilidades da próxima sprint ficam explícitas.
- **Execução:** conferir branch e árvore Git, revisão e evidências da Sprint 1; cruzar a matriz com a SPEC e a tabela de encerramento abaixo.

### S2-02 Validar assinatura e parsers candidatos

- **Entrada:** ADR 0001, [vetores assinados](../contracts/vectors/signed/), vetores JCS/C14N e candidatos a runtime, bibliotecas e parsers.
- **Entrega:** provas reproduzíveis em `spikes/` sobre os parsers que os serviços usarão, com versões fixadas e evidência sanitizada em `docs/sprint-2/evidence/`.
- **Aceite:** assinar e verificar ECDSA P-256/SHA-256 em DER e ML-DSA-65 puro no runtime escolhido, sem subprocesso por assinatura. JSON/JCS e XML/Exclusive C14N 1.0 sem comentários conferem com bytes de referência; no XML, o negócio recebe o mesmo nó validado e verificado.
- **Execução:** rodar vetores estáticos e mensagens recém-assinadas com chaves efêmeras, incluindo rejeição de entrada inválida. Se S2-03 mudar runtime, binding ou parser, repetir as provas afetadas antes de aprovar a stack.

### S2-03 Validar mTLS nos caminhos REST/SOAP e fechar o gate

- **Entrada:** provas S2-02, [SPEC §2](../SPEC.md#2-arquitetura-e-execução), ADR 0001 e [modelo de ameaças](security/threat-model.md).
- **Entrega:** troca mínima REST e SOAP pelos clientes e servidores candidatos, em processos separados, sem serviços de negócio. Complementar ADR 0001 com escolhas, versões efetivas, forma de observação, comandos, evidências e limitações.
- **Aceite:** nos três enlaces previstos (gestora–plataforma, plataforma–custodiante e plataforma–administrador), observar TLS 1.3 e o grupo exigido nas pontas, em cenários separados para X25519 e X25519MLKEM768. Validar mTLS, cadeia/nome do servidor e identidade ligada à política; incompatibilidade falha sem fallback. Carregar WSDL ou mostrar configuração não prova a troca.
- **Execução:** reproduzir conexões novas com certificados de laboratório; verificar grupo, suíte e autenticação pela API confiável do transporte ou terminador. Se a terminação mudar, proteger o trecho interno e a propagação de identidade/metadados, atualizar SPEC, ADR e ameaças conforme o impacto e prever o custo nas medições futuras. **Sem evidência completa, não iniciar S2-04.**

### S2-04 Preparar ambiente e persistência

- **Entrada:** stack aprovada e [modelo de persistência (§3)](../SPEC.md#3-modelo-de-domínio-e-persistência).
- **Entrega:** Compose em `deploy/`, migrações iniciais, papéis/bases independentes, cadastros sintéticos e scripts de preparação. Evoluir as tabelas nas tasks dos respectivos serviços.
- **Aceite:** instalação limpa sem edição manual de banco; versões fixadas; bancos e credenciais isolam plataforma, custodiante e administrador, mesmo se a instância for compartilhada. Dados sobrevivem ao reinício e credenciais não são versionadas.
- **Execução:** subir a infraestrutura, aplicar migrações e cadastros, testar transações, unicidade e isolamento das credenciais no banco real. Documentar inicialização e limpeza de recursos do cenário sem apagar ambientes alheios.

### S2-05 Integrar os controles C1

- **Entrada:** stack aprovada, infraestrutura, [contrato de mensagens](../contracts/messages/) e [SPEC §5](../SPEC.md#5-proteção-criptográfica).
- **Entrega:** adaptadores reutilizáveis de `crypto` e transporte; mTLS, identidade vinculada a `senderId`, política inicial C1, autorização de ação/carteira, registro de chaves e verificação de envelopes de requisição, resposta e erro. Nenhuma regra financeira no provedor.
- **Aceite:** cadeia, nome, grupo, política, chave autorizada, assinatura, validade, ambiente, destinatário e correlação verificados conforme o tipo; conferir caminho REST ou ação SOAP com o conteúdo protegido. Autenticação, validade e autorização precedem a devolução de qualquer resultado idempotente. Usar limites da SPEC, parser XML restrito e chaves privadas distintas para TLS e mensagem, fora do Git.
- **Execução:** verificar com adaptadores reais os vetores e os negativos C1, incluindo certificado/identidade inválidos, chave não autorizada, adulteração, expiração, destinatário/ambiente incorretos e entradas ambíguas ou fora dos limites. As tasks dos endpoints repetem os negativos pertinentes no serviço e verificam ausência de efeito.

### S2-06 Registrar e consultar operações da gestora

- **Entrada:** [contrato REST da plataforma](../contracts/openapi/platform.yaml), schemas de boleta/eventos, persistência e controles C1.
- **Entrega:** `POST /v1/operations` e `POST /v1/operations/{operationId}/status-queries`, registro imutável com UUID e versão 1, recibos de mensagens, eventos append-only e outbox para instrução válida na mesma transação do registro. Validar cadastros, carteira, datas e financeiro com decimais exatos.
- **Aceite:** `201` para primeiro registro, inclusive `REJECTED` local persistido com motivo e sem envio; erro de sintaxe não cria operação. Mesma identidade `(managerId, clientOrderId)` e mesmo negócio devolvem `200` e o mesmo UUID; negócio diferente retorna `409`/`IDEMPOTENCY_CONFLICT`. Consulta nova e assinada devolve o estado atual, não repete snapshot obsoleto nem expõe operação não autorizada.
- **Execução:** testar com banco real duas criações concorrentes, replay e reemissão, conflito, rejeição local, erro de esquema e consulta autorizada/não autorizada. Verificar resposta, correlação, contagem de operações/eventos e unicidade da intenção na outbox.

### S2-07 Implementar recebimento e consulta no custodiante REST

- **Entrada:** [contrato REST do custodiante](../contracts/openapi/custodian.yaml), mTLS/ECDSA e armazenamento próprio.
- **Entrega:** `POST /v1/instructions` e `POST /v1/instructions/{operationId}/status-queries`. Persistir inbox, recibos e histórico remoto próprio; responder com envelope assinado, inclusive ausência autenticada.
- **Aceite:** `202` significa `RECEIVED` persistido, nunca `ACCEPTED`. Deduplicar comandos por `(senderId, recipientId, messageType, operationId, instructionVersion)` e digest do negócio normalizado, em transação com o registro e o resultado. Diferenciar conflito de negócio de reutilização de `messageId` com conteúdo diferente; responder à reemissão válida com correlação atual.
- **Execução:** usar cliente REST real para testar aceite do recibo, consultas novas, `404`/`NOT_FOUND` assinado, reenvio concorrente, conflito e envelope expirado mesmo após processamento anterior.

### S2-08 Simular decisão e liquidação

- **Entrada:** custódia persistida, [transições financeiras](../contracts/domain/) e [cenários da SPEC §6](../SPEC.md#6-simulação-e-conciliação).
- **Entrega:** fixtures de aceitação, rejeição operacional e saldo insuficiente; relógio financeiro controlável pelo runner em interface de teste isolada. Persistir sequência remota, caixa, posição e lançamentos simulados.
- **Aceite:** distinguir `RECEIVED`, `ACCEPTED`, `PENDING_SETTLEMENT` e `SETTLED`; rejeição do custodiante tem motivo e não gera lançamentos; saldo insuficiente produz `SETTLEMENT_FAILED` sem débito parcial. Débito e crédito são atômicos e únicos por operação e tipo de lançamento.
- **Execução:** avançar o relógio financeiro sem esperar D+1 real, consultar o histórico REST e conferir lançamentos e saldos antes/depois, inclusive após repetir processamento ou reiniciar. Documentar o calendário simplificado.

### S2-09 Enviar e acompanhar a instrução pela plataforma

- **Entrada:** outbox S2-06, serviço custodiante S2-07/S2-08 e contratos de envio/consulta.
- **Entrega:** worker da plataforma e adaptador REST: preparar e persistir a tentativa, enviar, consultar e aplicar eventos remotos na projeção local com sequência própria. A plataforma assina como plataforma e preserva `managerId` no negócio.
- **Aceite:** persistir `SENT` antes da chamada de rede; só avançar com respostas verificadas e correlacionadas. O recibo leva a `RECEIVED`, não à aceitação. Consultas com novo `messageId` trazem estado atual; projeção não aceita salto de estado ou regressão e ignora fatos idênticos já aplicados.
- **Execução:** enviar uma boleta pela plataforma e ler o histórico completo até `SETTLED`; conferir também a projeção da rejeição do custodiante. Testar eventos repetidos, regressão e resposta não correlacionada sem avanço indevido.

### S2-10 Recuperar entregas inconclusivas

- **Entrada:** worker e históricos S2-09; [regras de idempotência e recuperação](../SPEC.md#idempotência-e-recuperação).
- **Entrega:** retomada pela outbox após reinício, timeout com entrega `UNKNOWN`, consulta antes de retransmitir, preenchimento de lacunas por consulta e retentativas persistidas para falhas transitórias.
- **Aceite:** só `NOT_FOUND` assinado e correlacionado autoriza retransmitir nesse caso; falha de consulta mantém `UNKNOWN` e nenhuma falha técnica cria rejeição financeira. Aplicar atrasos e limite da SPEC; esgotado o limite, preservar `BLOCKED` sem apagar o trabalho. Falhas de esquema, autorização ou assinatura não são retentadas automaticamente.
- **Execução:** testar perda de resposta após commit no custodiante, reinício após gravação na outbox e antes da confirmação, ausência autenticada, consulta inconclusiva, lacuna resolvida/não resolvida e esgotamento de tentativas. Conferir ordem consulta/envio, histórico e contagem de lançamentos.

### S2-11 Implementar o simulador SOAP do administrador

- **Entrada:** [WSDL e XSD](../contracts/soap/), segurança C1 e banco independente.
- **Entrega:** serviço SOAP 1.2 com `RegisterOperation` e `GetOperation`, snapshots terminais, inbox e recibos persistidos; confirmação, consulta e Faults assinados conforme contrato.
- **Aceite:** validar ação, namespace, estrutura e `SignedContent` antes do negócio; mapear decimais sem `float`. Registro, deduplicação e resultado são atômicos; repetição não duplica, conteúdo diferente conflita. Ausência usa `NOT_FOUND` no erro assinado em `Fault/Detail/Message`.
- **Execução:** chamar o serviço com o cliente SOAP aprovado sobre mTLS real, validar requisição/resposta/Fault contra XSD e conferir estado persistido. Cobrir repetição, conflito, consulta, ausência e rejeição de XML inválido sem efeito.

### S2-12 Atualizar e consultar o administrador pela plataforma

- **Entrada:** terminal do custodiante, outbox da plataforma e serviço SOAP S2-11.
- **Entrega:** adaptador SOAP da plataforma; enfileirar registro ao aplicar o terminal do custodiante, publicar `RegisterOperation` e obter o registro independente por `GetOperation` para a conciliação.
- **Aceite:** a intenção de atualizar o administrador é persistida na mesma transação da projeção terminal. Confirmar registro somente com resposta assinada e correlacionada; não confiar no `Code`/`Reason` externo do Fault. Indisponibilidade mantém liquidação e histórico intactos, entrega retomável e conciliação `NOT_READY`.
- **Execução:** testar o caminho real de registro/leitura, indisponibilidade temporária e recuperação por trabalho persistido, inclusive após resposta perdida; confirmar que a retomada não duplica o registro nem muda o estado financeiro.

### S2-13 Conciliar os três registros

- **Entrada:** boleta persistida, snapshot autenticado do custodiante, registro consultado no administrador e [SPEC §6](../SPEC.md#6-simulação-e-conciliação).
- **Entrega:** comparação por operação e versão, persistência dos snapshots/revisões e diferenças por campo e exposição do status conforme o contrato REST da plataforma.
- **Aceite:** comparar carteira, ativo, quantidade, taxa negociada, PU, financeiro, moeda, data prevista e resultado de liquidação com decimais exatos; não confundir data prevista com efetiva. Registro faltante gera `NOT_READY`; igualdade, `MATCHED`; diferença, `DIVERGENT` com valores por origem no resultado persistido. Não alterar automaticamente nenhum registro financeiro.
- **Execução:** rodar o caso igual, o incompleto e um caso com divergência sintética no administrador, controlada por interface de teste isolada. Verificar campo/valores persistidos e que a operação continua `SETTLED` mesmo com `DIVERGENT`.

### S2-14 Integrar demonstração e verificação C1

- **Entrada:** fluxo operacional S2-04–S2-13 e matriz de encerramento abaixo.
- **Entrega:** um ponto de entrada em `scripts/verify-sprint2/` para preparar ambiente, executar a suíte e o cenário da gestora e coletar evidências; documentar opção de rodar a demonstração separadamente. Consolidar logs estruturados dos serviços conforme a [SPEC §7](../SPEC.md#7-observabilidade-e-avaliação), sem segredos ou payload completo por padrão. Integrar o fluxo C1 à CI se o runner comportar o ambiente fixado; a reprodução local é obrigatória.
- **Aceite:** o script registra a boleta por REST, o worker a envia ao custodiante, o runner consulta com mensagens novas e avança o relógio financeiro, o worker atualiza o administrador por SOAP e o runner confirma `SETTLED` e `MATCHED` pela API. Nenhum salto manual no banco nem mock substitui banco, interfaces ou criptografia no aceite. Casos obrigatórios falhando, pulados ou com mecanismo diferente de C1 resultam em saída não zero.
- **Execução:** em ambiente limpo, rodar sucesso e negativos da matriz, com prazo de espera finito e isolamento de dados entre cenários. Conferir cardinalidade, históricos e metadados TLS observados; provocar uma falha controlada no runner para confirmar saída não zero. Gerar relatório por cenário, com revisão/estado da árvore, versões, parâmetros, resultado e código de saída.

### S2-15 Consolidar a entrega

- **Entrada:** commit S2-14 aprovado, matriz de aceite e revisão independente.
- **Entrega:** `docs/sprint-2/README.md`, índice de evidências sanitizadas, comandos reais, limitações e separação entre Sprint 1 demonstrada, C1 demonstrado e MVP pendente. Atualizar o README conforme o efetivamente executado.
- **Aceite:** toda linha obrigatória tem evidência rastreável; o diagnóstico identifica falhas e pendências sem tratá-las como aprovação. Nenhuma chave privada, credencial, volume ou relatório não sanitizado entra no Git.
- **Execução:** reexecutar o verificador em checkout limpo de S2-14 e registrar seu hash. Se a rodada exigir correção de código, abrir task corretiva, repetir as verificações afetadas e a integração antes do fechamento; S2-15 é documental.

## Arquitetura multiagente sequencial

O modelo segue a [Sprint 1](SPRINT-1.md#arquitetura-multiagente-sequencial): uma branch de trabalho, histórico linear, um executor por task e revisão por instância distinta. Os papéis podem ser reutilizados; o coordenador não toca outra implementação em paralelo. Este plano descreve a execução futura, não inicia agentes nem commits de implementação.

| Papel | Responsabilidade | Limite |
|---|---|---|
| Coordenador | Ordenar tasks, conferir baseline e árvore Git, delegar, aceitar/bloquear e criar o commit. | Não avançar com requisito obrigatório sem evidência. É o único que commita. |
| Arquitetura | Escopo, decisão da stack e consolidação. | Não aprovar serviços com base apenas nas provas da Sprint 1. |
| Criptografia / Segurança | Provas do runtime, TLS, parsers, chaves, assinatura, identidade, autorização e negativos. | Sem primitivas próprias, fallback ou relaxamento de controles; sem regras financeiras no provedor. |
| Persistência | Ambiente, migrações, isolamento e garantias transacionais. | Não alterar contratos ou introduzir broker. |
| Plataforma | Registro, consultas, projeção, outbox, integração REST e recuperação. | Não inferir estado remoto de timeout ou recibo. |
| REST/Custódia | Contrato REST, histórico remoto e efeitos simulados. | Não escrever no banco da plataforma. |
| SOAP | Serviço, cliente, mapeamento e Faults segundo WSDL/XSD. | Não substituir SOAP por chamada interna nem mudar contrato para ajustar o framework. |
| Domínio | Comparação dos snapshots e resultado de conciliação. | Não reclassificar a liquidação nem alterar registros de origem. |
| Validação | Verificador, cenários determinísticos, evidências e reprodução. | Não aprovar cenário com mock de enlace obrigatório, falha ou skip. |
| Revisor | Inspecionar diff e repetir verificações pertinentes contra o aceite. | Instância distinta do executor; não edita, não commita e só atua depois do executor. |

### Ciclo e pacote de passagem

1. **Preparar:** coordenador confere branch, `git status`, commit anterior, dependências e arquivos preexistentes. Delega apenas a task atual.
2. **Executar:** especialista altera apenas o escopo, testa e devolve arquivos, comandos, resultados, evidências e pendências. Não commita nem subdelega.
3. **Revisar:** revisor registra `APROVADO` ou `REQUER_CORRECAO`, com caminhos, motivos e resultados. Se necessário, o mesmo executor corrige e a revisão se repete antes de avançar.
4. **Concluir:** coordenador confere diff e evidência, adiciona explicitamente os arquivos da task, cria o commit e registra seu hash no histórico da execução e na passagem seguinte. Sem branches por agente, merges ou commits intermediários por task. Correções após commit são tasks identificadas e atômicas; não reescrever histórico publicado.

```text
Task: S2-NN
Commit base: <hash aprovado da task anterior>
Objetivo e entradas: <resultado, requisitos, contratos, ADRs e evidências relevantes>
Arquivos permitidos e fora do escopo: <limites da task>
Aceite: <condições verificáveis>
Execução: <comandos ou procedimento e evidências esperadas>
Commit planejado: <mensagem da tabela>
Restrições: não commitar, não iniciar outra task, não delegar
```

**Bloqueios:** grupo não observável, incompatibilidade entre parser/cliente e baseline, dependência indisponível, autorização incorreta ou duplicidade de efeito impedem avançar. Registrar diagnóstico, passos de reprodução e requisito afetado; corrigir no escopo ou submeter a mudança de requisito/arquitetura ao responsável. Não trocar serviços reais por mocks, relaxar a proteção ou registrar aprovação parcial como conclusão da task.

## Critérios de encerramento da sprint

| Entrega / cenário obrigatório | Tasks | Evidência esperada no ambiente fixado |
|---|---|---|
| Stack aprovada e C1 observado | S2-02–03, S2-05, S2-14 | Provas dos candidatos separadas do fluxo. No fluxo, grupo X25519, TLS 1.3, suíte e autenticação observados nos três enlaces, com envelopes ECDSA verificados. |
| Registro, envio, consultas e conciliação (**T01**) | S2-06–09, S2-11–14 | Um UUID rastreável, histórico até `SETTLED`, um débito e um crédito, um registro SOAP e `MATCHED`, sem intervenção manual no banco. |
| Rejeição e falha simulada (**T01**, SPEC §6) | S2-06, S2-08–09, S2-14 | Rejeição local com motivo e sem envio; rejeição operacional com motivo e sem liquidação; saldo insuficiente sem débito parcial. |
| Reenvio, concorrência e conflito (**T02**, **T09**) | S2-06–08, S2-11–12, S2-14 | Replay e reemissão válida sem novo efeito; conteúdo diferente na mesma identidade ou reutilização conflitante de `messageId` rejeitados; conferência de unicidade na plataforma e nos destinatários. |
| Timeout, indisponibilidade e reinício (**T03**, **T04**, **T13**) | S2-10, S2-12, S2-14 | Consulta antes de retransmitir, retomada sem duplicidade, `UNKNOWN`/`BLOCKED` conforme o caso e `NOT_READY` enquanto o administrador não confirma; liquidação preservada. |
| Controles de mensagem, parser e identidade em C1 (**recorte de T05**, **T07**, **T08**) | S2-03, S2-05–07, S2-11, S2-14 | Rejeições esperadas sem efeito indevido, sem resolução externa no XML nem fallback TLS. |
| Histórico e divergência (**T12**) | S2-09–10, S2-13–14 | Nenhum retrocesso por evento antigo/duplicado; lacuna recuperada por consulta ou sem avanço; `DIVERGENT` por campo, sem desfazer `SETTLED`. |
| Evidência e reprodução | S2-14–15 | Comando único do verificador, execução em revisão limpa, relatório sanitizado e rastreabilidade por operação, mensagem e correlação, com versão da política, tentativa, `keyId`, mecanismos e resultado. |

O aceite desta sprint **não** equivale à aprovação integral de T01–T14. T06, T10 e T11 ficam para perfis duplo e migração/rotação. Para T14, usar os vetores e comprovar os caminhos exercitados nesta sprint sem declarar aprovação da matriz de seis configurações nos dois adaptadores. Encerrar apenas com todos os critérios obrigatórios de C1 verificados, sem falhas ou skips mascarados.
