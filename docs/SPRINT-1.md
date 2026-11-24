# Plano de desenvolvimento da sprint 1

A sprint entrega contratos e vetores de mensagem verificáveis, o modelo da boleta e dos estados, o conteúdo assinado, o modelo de ameaças e uma prova executável de ECDSA, ML-DSA e TLS com X25519 e X25519MLKEM768. A escolha da stack deve resultar dessas provas e registrar suas limitações antes da implementação dos conectores.

**Base:** [README](../README.md) e [SPEC](../SPEC.md). **Status:** planejamento; tasks ainda não executadas. **Execução:** sequencial, com uma task ativa e um commit Conventional Commits por task concluída.

## Escopo e regras de execução

As implementações desta sprint são schemas, validadores, fixtures e provas técnicas isoladas. Serviços financeiros, banco, outbox/inbox, conectores operacionais, migração sob carga e benchmarks completos pertencem às próximas sprints. Um servidor mínimo de handshake é parte da prova TLS, não um conector financeiro.

Cada task inclui implementação, testes pertinentes, evidência e revisão no mesmo commit. Não criar tasks separadas apenas para testar código recém-escrito. Os caminhos abaixo são os destinos planejados; extensões de código e ferramentas serão definidas pela stack. As provas ficam em `spikes/`, sem introduzir antecipadamente uma arquitetura de produção.

As tasks seguem estritamente a ordem S1-01 → S1-19. Cada uma depende do commit aprovado da anterior, além das entradas técnicas indicadas. A divisão prioriza mudanças revisáveis, não a distribuição de trabalho simultâneo. Não há promessa de duração por task: a viabilidade criptográfica e o suporte dos bindings são o principal risco da semana.

## Backlog de commits

| Task | Resultado | Agente executor | Commit planejado |
|---|---|---|---|
| S1-01 | Baseline de requisitos e escopo | Arquitetura | `docs(sprint1): registra especificacao e escopo da sprint` |
| S1-02 | Modelo de ameaças | Segurança | `docs(security): define ameacas e fronteiras de confianca` |
| S1-03 | Ambiente reproduzível das provas | Criptografia | `build(spikes): prepara ambiente das provas criptograficas` |
| S1-04 | Prova ECDSA P-256 | Criptografia | `feat(spikes): demonstra assinatura e verificacao ECDSA` |
| S1-05 | Prova ML-DSA-65 | Criptografia | `feat(spikes): demonstra assinatura e verificacao ML-DSA` |
| S1-06 | Prova TLS com X25519 | Criptografia | `feat(spikes): comprova negociacao TLS com X25519` |
| S1-07 | Prova TLS com X25519MLKEM768 | Criptografia | `feat(spikes): comprova negociacao TLS hibrida` |
| S1-08 | Decisão fundamentada da stack | Arquitetura | `docs(adr): registra stack validada e limitacoes de suporte` |
| S1-09 | Modelo verificável da boleta | Domínio | `feat(contracts): define schema e regras da boleta` |
| S1-10 | Transições e eventos | Domínio | `feat(contracts): especifica estados e eventos da operacao` |
| S1-11 | Envelope e conteúdo assinado | Segurança | `feat(contracts): define envelope e perfis de assinatura` |
| S1-12 | Canonicalização JSON | Criptografia | `test(contracts): adiciona vetores de canonicalizacao JSON` |
| S1-13 | Canonicalização XML | Criptografia | `test(contracts): adiciona vetores de canonicalizacao XML` |
| S1-14 | Contrato REST da plataforma | Contratos | `feat(api): especifica contrato REST da plataforma` |
| S1-15 | Contrato REST do custodiante | Contratos | `feat(api): especifica contrato REST do custodiante` |
| S1-16 | Contrato SOAP do administrador | Contratos | `feat(api): especifica contrato SOAP do administrador` |
| S1-17 | Vetores assinados dos contratos | Criptografia | `test(crypto): adiciona vetores assinados JSON e XML` |
| S1-18 | Verificação integrada reproduzível | Validação | `test(sprint1): integra verificacao dos contratos e provas` |
| S1-19 | Relatório e congelamento dos contratos | Arquitetura | `docs(sprint1): consolida evidencias e contratos da entrega` |

### S1-01 Registrar a baseline

- **Entrada:** README, SPEC e este plano; verificar o estado do Git antes de trabalhar.
- **Entrega:** versionar a especificação revisada e este plano, se ainda não estiverem versionados. Explicitar requisitos da sprint e itens adiados em `docs/sprint-1/scope.md`.
- **Aceite:** cada entrega solicitada está ligada a uma task; nenhum serviço ou benchmark do MVP foi incluído como obrigação desta sprint.
- **Verificação:** revisão cruzada de escopo e referências. Preservar alterações preexistentes; não incluí-las automaticamente por estarem no diretório de trabalho.

### S1-02 Definir ameaças e fronteiras de confiança

- **Entrada:** baseline e seções de proteção, identidade e recuperação da SPEC.
- **Entrega:** `docs/security/threat-model.md`, com ativos, atores, fronteiras, capacidades do atacante, controles e riscos residuais.
- **Aceite:** cobrir adulteração, replay, duplicação, troca de destinatário/ambiente, downgrade, substituição de chave, XML wrapping/XXE, vazamento de segredos e abuso de tamanho. Distinguir autenticação TLS tradicional de autenticação pós-quântica da mensagem e explicitar a confiança na plataforma.
- **Verificação:** cada ameaça aponta para teste nesta sprint ou teste futuro da SPEC. Comprometimento do host e proteção física de chaves constam como limitações, sem prometer solução no MVP.

### S1-03 Preparar o ambiente das provas

- **Entrada:** requisitos criptográficos e ameaças; a stack ainda é candidata.
- **Entrega:** ambiente Linux reproduzível em `deploy/spikes/`, dependências fixadas, instruções em `spikes/README.md`, manifesto de versões e regras para excluir segredos e arquivos temporários do Git.
- **Aceite:** iniciar o ambiente limpo e carregar o runtime e os bindings escolhidos. Inventariar as capacidades disponíveis sem tratá-las como prova de execução dos algoritmos.
- **Verificação:** comando de diagnóstico registra versões efetivamente carregadas e configuração do ambiente. Validar versões nas fontes oficiais no momento da implementação; não depender apenas do OpenSSL instalado no host.

### S1-04 Executar a prova ECDSA

- **Entrada:** ambiente S1-03 e um payload fixo independente dos contratos finais.
- **Entrega:** prova em `spikes/signatures/ecdsa/` que gera chave, assina e verifica com P-256/SHA-256 e representação DER; relatório sanitizado em `docs/sprint-1/evidence/ecdsa.json`.
- **Aceite:** mensagem original aceita; mensagem adulterada, assinatura adulterada e chave pública diferente rejeitadas. A biblioteca é chamada pelo runtime, sem subprocesso por assinatura.
- **Verificação:** executar os casos positivos e negativos e registrar algoritmo, biblioteca, resultado e comando. Chaves privadas são geradas localmente e não entram no commit.

### S1-05 Executar a prova ML-DSA

- **Entrada:** padrão de execução e evidência definido em S1-04.
- **Entrega:** prova em `spikes/signatures/ml-dsa/` usando ML-DSA-65 puro, mensagem completa e contexto vazio; evidência sanitizada correspondente.
- **Aceite:** casos positivos e negativos equivalentes aos de ECDSA; confirmar que o binding oferece a operação necessária sem implementar primitivas ou pré-hash próprios.
- **Verificação:** registrar parâmetros e tamanhos observados, comparando-os à documentação normativa aplicável. Distinguir tamanho da assinatura bruta de Base64 e tamanho da chave bruta de sua codificação em arquivo.

### S1-06 Confirmar TLS tradicional

- **Entrada:** ambiente candidato, identidade e controles da SPEC.
- **Entrega:** cliente e servidor mínimos em `spikes/tls/`, gerador de CA/certificados de laboratório e cenário TLS 1.3 com grupo restrito a X25519.
- **Aceite:** handshake real, mTLS validado, grupo negociado igual ao exigido, retomada e 0-RTT desabilitados; certificado não confiável e nome de servidor incorreto causam falha.
- **Verificação:** capturar protocolo, grupo observado, suíte e identidade do certificado a partir da biblioteca/terminador confiável. A configuração desejada não substitui a evidência negociada. A CLI pode auxiliar o diagnóstico, mas não comprova sozinha a viabilidade do runtime candidato.

### S1-07 Confirmar TLS híbrido

- **Entrada:** harness TLS de S1-06.
- **Entrega:** cenário X25519MLKEM768 no mesmo harness, com evidência sanitizada do handshake e teste de incompatibilidade.
- **Aceite:** confirmar o grupo híbrido efetivo. Um cliente limitado a X25519 contra servidor que exige o híbrido deve falhar, sem fallback; manter suíte e autenticação tradicional controladas entre cenários.
- **Verificação:** repetir com processo e conexão novos. Registrar o suporte de cliente, servidor, binding e mecanismo de observação; ausência de informação sobre o grupo é impedimento para aprovação.

### S1-08 Registrar a decisão da stack

- **Entrada:** provas e evidências de S1-03 a S1-07.
- **Entrega:** `docs/adr/0001-stack.md` com linguagem/runtime, bibliotecas, servidores candidatos, versões, decisão de terminação TLS e matriz de suporte observado. Atualizar apenas decisões correspondentes da SPEC quando necessário.
- **Aceite:** assinatura e verificação dos dois algoritmos e negociação dos dois grupos estão comprovadas no caminho técnico escolhido. Indicar o que foi exercitado por API, o que foi apenas diagnóstico de CLI e o que ainda depende de integração futura.
- **Verificação:** cada afirmação de suporte possui comando e evidência. Limitação impeditiva exige correção e nova prova; não substituir ML-DSA por mock nem TLS híbrido por algoritmo tradicional para liberar a etapa.

### S1-09 Especificar e validar a boleta

- **Entrada:** modelo financeiro da SPEC e ferramentas definidas em S1-08.
- **Entrega:** schema em `contracts/schemas/`, fixtures em `fixtures/boletas/` e validador isolado em `tests/contracts/`, sem serviço ou banco.
- **Aceite:** campos, enums, escalas, limites, cadastros de referência e imutabilidade definidos; verificar quantidade × PU, arredondamento, overflow e datas. Diferenciar `clientOrderId` de `operationId` e a criação da instrução já identificada.
- **Verificação:** fixture válida e casos negativos de precisão, financeiro, data, campo desconhecido e cadastro incompatível. Regras sem expressão no schema recebem validação semântica explícita.

#### Task corretiva S1-09-C1 — revalidação da boleta

Após o commit preexistente `462454e`, corrigir a dependência do contexto decimal global e verificar o schema e a fixture com motor JSON Schema fixado no runtime aprovado. Reexecutar os testes de boleta e registrar evidência; revisão independente antecede o commit atômico `fix(contracts): revalida boleta no ambiente aprovado`. Não altera os contratos posteriores.

### S1-10 Especificar transições e eventos

- **Entrada:** boleta e estados da SPEC.
- **Entrega:** tabela de transições em `contracts/domain/`, schema de evento e fixtures de sequências válidas e inválidas, com verificador isolado.
- **Aceite:** definir estado inicial, terminais, origem da rejeição, sequência e eventos intermediários. Estado financeiro, entrega e conciliação permanecem independentes; timeout não gera rejeição financeira.
- **Verificação:** cobrir transição proibida, regressão, evento repetido e lacuna. Descrever a recuperação por consulta; não implementar worker ou histórico persistido nesta task.

#### Task corretiva S1-10-C1 — revalidação de eventos

Após o commit preexistente `b46a2b8`, revalidar tabela, sequências e schema com o runtime aprovado e o motor JSON Schema fixado; registrar evidência e submeter a revisão independente antes do commit atômico. Não altera mensagens nem implementa serviços.

### S1-11 Especificar envelope e conteúdo assinado

- **Entrada:** S1-02, schemas de boleta e eventos.
- **Entrega:** schemas e documento em `contracts/messages/` com tipos de mensagem, campos protegidos, payloads, signatários, perfis e regras de correlação, validade e política.
- **Aceite:** definir a obrigatoriedade por tipo, inclusive criação sem UUID, respostas e erros assinados. Vincular algoritmo e `keyId` ao conteúdo protegido; perfil duplo exige ambas as assinaturas. Diferenciar identidade lógica de comando e identidade de mensagem; consultas novas não reutilizam estado antigo.
- **Verificação:** exemplos estruturais válidos e inválidos para ausência de contexto, versão não suportada e signatários incompatíveis. Marcar valores ilustrativos de assinatura como não criptográficos até S1-17.

#### Task corretiva S1-11-C1 — revalidação do envelope

Após o commit preexistente `66df679`, resolver referências dos schemas e revalidar todos os exemplos com JSON Schema fixado no runtime aprovado. Registrar evidência e submeter a revisão independente antes do commit atômico `fix(contracts): revalida envelope no ambiente aprovado`. O histórico remoto de `QUERY_INSTRUCTION_RESULT` requer correção semântica em S1-15, não nesta task.

### S1-12 Produzir vetores de canonicalização JSON

- **Entrada:** envelope de S1-11.
- **Entrega:** casos em `contracts/vectors/json/` contendo entrada, bytes canônicos esperados e digest de conferência, com executor baseado em biblioteca JCS.
- **Aceite:** confirmar exatamente os bytes de `{protected, payload}`; preservar decimais como strings; rejeitar propriedades duplicadas antes de canonicalizar.
- **Verificação:** testar ordem de propriedades, Unicode, escapes e tipos inválidos. Usar vetores de referência ou uma segunda implementação para conferir o esperado; não gerar a expectativa dinamicamente com a mesma função sob teste.

#### Task corretiva S1-12-C1 — revalidação JCS

Após o commit preexistente `73e3197`, reexecutar os vetores e a suíte completa no CPython Linux aprovado com biblioteca JCS fixada por versão e hash, preservando a evidência histórica e as dependências anteriores. Registrar evidência, incluindo falhas deliberadas, e submeter a revisão independente antes do commit atômico `test(contracts): revalida canonicalizacao JSON no ambiente aprovado`. Não altera contratos de domínio nem antecipa S1-13 ou S1-15.

### S1-13 Produzir vetores de canonicalização XML

- **Entrada:** envelope de S1-11 e regras XML da SPEC.
- **Entrega:** XSD comum de `SignedContent` e vetores em `contracts/vectors/xml/`, com bytes esperados e executor de Exclusive C14N sem comentários.
- **Aceite:** namespace, caminho único do conteúdo e elementos assinados definidos; parser sem entidades externas/DTD; processamento do mesmo nó verificado. Preservar whitespace conforme a canonicalização, sem limpeza prévia arbitrária.
- **Verificação:** namespaces, atributos, escapes e whitespace; rejeição de conteúdo duplicado/substituído e resolução externa. Conferir expectativas por referência independente, como em S1-12.

### S1-14 Publicar o contrato REST da plataforma

- **Entrada:** modelos, envelope e vetores JSON.
- **Entrega:** `contracts/openapi/platform.yaml`, schemas referenciados e exemplos de criação e consulta, respostas e erros.
- **Aceite:** cobrir os dois endpoints da SPEC, mTLS, correlação, código de criação, repetição idempotente, conflito, ausência e rejeição local. Definir como operação persistida rejeitada é identificada na resposta.
- **Verificação:** validar OpenAPI e todas as referências/exemplos com ferramentas fixadas. Não exigir servidor implementado nem descrever como disponível um endpoint apenas especificado.

### S1-15 Publicar o contrato REST do custodiante

- **Entrada:** contrato comum, eventos e semântica da plataforma.
- **Entrega:** `contracts/openapi/custodian.yaml`, exemplos de recibo, consulta, decisão, estado terminal e ausência autenticada.
- **Aceite:** `202` significa recebimento persistido, não aceitação; consulta fornece snapshot e sequência para recuperação. Definir conflito de identidade lógica e consistência entre caminho e conteúdo protegido.
- **Verificação:** validação estrutural e semântica dos exemplos, incluindo timeout seguido de consulta como sequência de mensagens, sem implementar transporte ou persistência.

### S1-16 Publicar o contrato SOAP do administrador

- **Entrada:** modelo financeiro, envelope e XSD comum de S1-13.
- **Entrega:** `contracts/soap/administrator.wsdl`, XSDs e exemplos SOAP 1.2 de `RegisterOperation`, `GetOperation`, respostas e Faults.
- **Aceite:** ações, namespaces, tipos, correlação, segurança e representação de erro coerentes com a SPEC. Mapeamento de nomes JSON/XML e regras de decimais documentados, sem perda de significado.
- **Verificação:** validar WSDL, resolver imports locais e validar exemplos contra XSD; carregar o contrato com a ferramenta cliente candidata. Isso comprova leitura do contrato, não interoperabilidade de um serviço ainda inexistente.

### S1-17 Produzir vetores assinados dos contratos

- **Entrada:** provas criptográficas, canonicalização e contratos REST/SOAP aprovados.
- **Entrega:** corpus em `contracts/vectors/signed/` com mensagens JSON/XML, bytes assinados, chaves públicas, assinaturas e resultados esperados; gerador de novos casos com chaves temporárias.
- **Aceite:** verificar ECDSA, ML-DSA e perfil duplo sobre os conteúdos dos contratos; cobrir requisição, resposta e erro assinado. Perfil duplo é apenas verificação isolada nesta sprint, sem política de migração.
- **Verificação:** original aceito; payload/contexto adulterado, assinatura removida e chave trocada rejeitados. Vetores estáticos usam relógio de referência declarado para validade. Não exigir que assinaturas aleatórias regeneradas sejam byte a byte iguais às armazenadas; exigir verificação correta. Nenhuma chave privada é versionada.

### S1-18 Integrar a verificação da sprint

- **Entrada:** todos os validadores, contratos, vetores e provas anteriores.
- **Entrega:** um ponto de entrada em `scripts/verify-sprint1/`, comando documentado e relatório por caso. Integrar à CI se o runner suportar integralmente o ambiente fixado; a execução local reproduzível é obrigatória.
- **Aceite:** em ambiente limpo, um comando valida modelos/contratos, verifica vetores e executa as provas de assinatura e dos dois grupos TLS. Propagar falhas por código de saída; dependência indisponível não vira teste aprovado.
- **Verificação:** executar uma vez com sucesso e introduzir temporariamente uma entrada inválida para confirmar falha do runner. Reverter a perturbação antes do commit. Logs e manifesto identificam versões e revisão de código testada; não executar o benchmark completo.

### S1-19 Consolidar a entrega

- **Entrada:** execução integrada aprovada e revisão independente.
- **Entrega:** `docs/sprint-1/README.md`, índice das evidências, matriz requisito → artefato → verificação, limitações e roteiro de reprodução. Atualizar o README com o que foi efetivamente entregue e links para os contratos.
- **Aceite:** nenhum requisito obrigatório sem evidência; contratos versionados e alterações futuras submetidas a revisão de compatibilidade. Diferenciar PoCs de funcionalidades do MVP e registrar pendências das próximas sprints.
- **Verificação:** reexecutar o comando integrado sobre o commit S1-18 e registrar seu hash. O commit S1-19 contém apenas consolidação documental; se a revisão exigir código, corrigir antes de congelar a entrega e repetir os testes afetados.

## Arquitetura multiagente sequencial

O coordenador controla o Git e a passagem entre tasks. Os especialistas trabalham por delegação, um de cada vez. Esta arquitetura é um plano de execução futura; a criação deste documento não inicia as tasks nem cria seus commits.

| Papel | Responsabilidade | Limite de atuação |
|---|---|---|
| Coordenador | Selecionar task, fornecer contexto, verificar dependências, solicitar revisão e criar o único commit. | Não inicia outra task enquanto a atual não estiver concluída ou explicitamente bloqueada. |
| Arquitetura | Baseline, decisão da stack e consolidação. | Não declara suporte sem evidência das provas. |
| Segurança | Ameaças, fronteiras, envelope e critérios negativos. | Não reduz requisito criptográfico para contornar falha de biblioteca. |
| Criptografia | Ambiente, assinaturas, TLS, canonicalização e vetores. | Usa bibliotecas; não implementa primitivas próprias ou conectores financeiros. |
| Domínio | Boleta, regras financeiras e estados. | Não implementa persistência ou simulação operacional. |
| Contratos | OpenAPI, WSDL/XSD e exemplos. | Não implementa servidores de negócio. |
| Validação | Runner integrado e reprodução. | Não substitui testes reais por mocks para aprovar viabilidade. |
| Revisor | Inspecionar diff, executar verificações pertinentes e apontar desvios. | Atua após o executor encerrar; não escreve código nem cria commit. |

Os papéis são reutilizáveis e não precisam corresponder a agentes simultaneamente residentes. O revisor deve ser uma instância distinta do executor daquela task, com contexto suficiente para verificar o requisito original. O coordenador fica aguardando enquanto um especialista executa; não mantém trabalho de implementação concorrente. Subagentes não delegam a outros agentes.

O ciclo de cada task é:

1. **Preparar:** coordenador confere branch, `git status`, commit anterior e arquivos preexistentes; entrega somente a task atual ao especialista.
2. **Executar:** especialista altera os arquivos do escopo, executa verificações e devolve diff, resultados e limitações. Não faz commit.
3. **Revisar:** após o executor encerrar, o revisor compara a alteração com os critérios de aceite e retorna aprovação ou pendências objetivas.
4. **Corrigir:** se houver pendências, o revisor encerra e o mesmo executor corrige a mesma task. Repetir revisão sem iniciar a próxima.
5. **Concluir:** coordenador confere o diff final, adiciona explicitamente os arquivos da task, cria o commit planejado e registra o hash na passagem para a próxima task.

Não usar branches por agente, merges, commits de revisão ou commits intermediários para a mesma task. A execução usa uma branch de trabalho e histórico linear. Alterações não relacionadas permanecem fora do commit. Se surgir correção após uma task já commitada, criar uma nova task corretiva com seu próprio commit e atualizar o plano; não reescrever histórico publicado para preservar artificialmente a contagem original.

### Pacote de passagem entre agentes

Cada delegação deve incluir:

```text
Task: S1-NN
Commit base: <hash aprovado da task anterior>
Objetivo: <um resultado do backlog>
Entradas: <seções e arquivos relevantes>
Arquivos permitidos: <escopo da alteração>
Fora do escopo: <limites específicos>
Aceite: <condições verificáveis>
Verificação: <comandos ou procedimento esperado>
Commit planejado: <mensagem Conventional Commits>
Restrições: não commitar, não iniciar outra task, não delegar
```

O executor devolve arquivos alterados, comandos e resultados, evidências e pendências. O revisor devolve `APROVADO` ou `REQUER_CORRECAO`, com caminhos e motivos. O coordenador registra task, hash do commit e resumo de verificação no histórico da execução; registros necessários à reprodução entram no commit da própria task, sem criar commits apenas para atualizar status.

### Tratamento de bloqueios

Falha de assinatura/verificação, grupo TLS não observável, binding incompatível ou contrato inválido bloqueia o avanço. O especialista registra diagnóstico e evidências locais e devolve ao coordenador. Uma tentativa falha não gera commit de task concluída nem habilita implementação dos conectores.

O coordenador pode devolver a task ao executor para corrigir ambiente ou dependências dentro do escopo. Se a correção alterar uma decisão já consolidada, inserir uma task corretiva atômica antes de continuar. Se exigir mudança de requisito do projeto, apresentar o diagnóstico e a decisão necessária ao responsável; não reduzir unilateralmente a proteção. Limitações não impeditivas podem seguir documentadas quando todos os critérios obrigatórios continuam satisfeitos.

## Critérios de encerramento da sprint

| Entrega solicitada | Tasks | Evidência de aceite |
|---|---|---|
| Modelo da boleta | S1-09 | Schema, fixtures e validações estruturais/financeiras. |
| Transições de estado | S1-10 | Tabela e sequências verificadas, incluindo casos inválidos. |
| Contratos REST/SOAP | S1-14 a S1-16 | OpenAPI, WSDL/XSD e exemplos validados. |
| Conteúdo assinado e vetores | S1-11 a S1-13 e S1-17 | Bytes canônicos, chaves públicas, assinaturas verificadas e casos negativos. |
| Ameaças consideradas | S1-02 | Fronteiras, controles, riscos e ligação aos testes. |
| ECDSA e ML-DSA executados | S1-04 e S1-05 | Provas reais pelo runtime escolhido, com rejeição de adulteração. |
| Dois grupos TLS confirmados | S1-06 e S1-07 | Handshakes reais, grupo observado e falha sem fallback. |
| Stack e limitações registradas | S1-08 | ADR baseada em evidências, anterior aos conectores. |
| Reprodução e entrega | S1-18 e S1-19 | Comando único, manifesto, revisão testada e relatório. |

A sprint não exige passar integralmente T01–T14 da SPEC, que cobrem o MVP completo. Ela prepara seus contratos e valida os controles isolados aplicáveis. Fluxo financeiro persistido, recuperação operacional, seis configurações nos conectores e migração sob carga serão comprovados nas sprints seguintes.

O encerramento exige todas as entregas da tabela, sem testes obrigatórios pulados ou suporte presumido pela versão da biblioteca. Os 19 commits planejados representam o caminho nominal; qualquer task corretiva deve ser identificada e manter a mesma regra de uma alteração atômica por commit.
