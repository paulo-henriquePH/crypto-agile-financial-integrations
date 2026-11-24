# Envelope e conteúdo assinado v1

Contrato experimental definido a partir da SPEC §§4–5 e do [modelo de ameaças](../../docs/security/threat-model.md), sem alegação de compatibilidade JWS ou WS-Security. O [schema](envelope.schema.json) e o [catálogo](types.json) definem o envelope lógico; JSON e XML preservam o mesmo significado. O XSD e os bytes canônicos serão entregues em S1-12/13. A sintaxe lógica aqui não substitui validação XML.

**Todas as assinaturas dos [exemplos](examples.json) são ilustrativas e não criptográficas.** Decodificam para `NOT_A_SIGNATURE`; nenhum caso comprova autenticidade. S1-17 substituirá essa finalidade por vetores criptográficos verificáveis. O validador retorna `cryptographicallyVerified: false`, mesmo quando a estrutura está correta.

## Conteúdo protegido

JSON contém exatamente `protected`, `payload` e `signatures`; os bytes a assinar serão UTF-8 de JCS aplicado a `{protected, payload}`. A região assinada inclui integralmente a lista ordenada de signatários. Decimais financeiros permanecem strings. JSON duplicado é rejeitado antes da canonicalização.

XML terá exatamente um `SignedContent`, contendo `Protected` e `Payload` no namespace `urn:cafi:v1`, com assinaturas irmãs. Assina-se o elemento inteiro por Exclusive XML C14N 1.0 sem comentários e sem lista adicional de prefixos. Não remover whitespace antes de verificar. Parser sem DTD, entidades externas, XInclude ou resolução externa; processar o mesmo nó verificado. Body duplicado, conteúdo substituído e cabeçalhos externos que tentem redefinir ação/destino serão rejeitados nas provas XML e serviços futuros.

Campos protegidos obrigatórios para todos os tipos: `schemaVersion = "1.0"`, `messageId` UUID, `messageType`, `senderId`, `recipientId`, `environment`, `instructionVersion = 1`, `issuedAt`, `expiresAt`, `policyVersion` inteiro positivo, `signatureProfile`, `canonicalization` e `signers`. `operationId` e `requestMessageId` seguem a tabela. Campo opcional ausente não pode ser representado por `null`. Propriedades desconhecidas e versões não suportadas falham.

Identificadores de participante, ambiente e chave usam 1–64 caracteres ASCII alfanuméricos, `_` ou `-`. UUIDs usam forma minúscula com hífens. Horários são UTC com sufixo `Z`; o validador isolado suporta até seis casas fracionárias e não suporta segundos intercalares. A seleção do ambiente e das identidades autorizadas vem da configuração local, nunca somente dos nomes recebidos.

## Tipos e obrigatoriedade

| Tipo | Emissor → destinatário | `operationId` | `requestMessageId` | Payload |
|---|---|---|---|---|
| CREATE_OPERATION | Gestora → plataforma | Proibido: UUID ainda inexistente | Proibido | Boleta de criação, incluindo `clientOrderId`; `senderId` determina gestora autorizada. |
| QUERY_OPERATION | Gestora → plataforma | Obrigatório | Proibido | Objeto vazio; operação/contexto estão protegidos. |
| SUBMIT_INSTRUCTION | Plataforma → custodiante | Obrigatório | Proibido | `{managerId, boleta}`. |
| QUERY_INSTRUCTION | Plataforma → custodiante | Obrigatório | Proibido | Objeto vazio. |
| REGISTER_OPERATION | Plataforma → administrador | Obrigatório | Proibido | `{managerId, boleta, state, sequence}`; estado terminal, com motivo e origem quando aplicáveis. |
| QUERY_ADMIN_RECORD | Plataforma → administrador | Obrigatório | Proibido | Objeto vazio. |
| CREATE_OPERATION_RESULT | Plataforma → gestora | Obrigatório, inclusive rejeição local persistida | Obrigatório | Snapshot de criação: REGISTERED, VALIDATED ou REJECTED. |
| QUERY_OPERATION_RESULT | Plataforma → gestora | Obrigatório | Obrigatório | Snapshot, eventos, entrega e conciliação. |
| SUBMIT_INSTRUCTION_RESULT | Custodiante → plataforma | Obrigatório | Obrigatório | `{state: "RECEIVED", sequence}`; recebimento persistido, sem aceitação implícita. |
| QUERY_INSTRUCTION_RESULT | Custodiante → plataforma | Obrigatório | Obrigatório | Snapshot e eventos para recuperação. |
| REGISTER_OPERATION_RESULT | Administrador → plataforma | Obrigatório | Obrigatório | Snapshot terminal registrado. |
| QUERY_ADMIN_RECORD_RESULT | Administrador → plataforma | Obrigatório | Obrigatório | Snapshot terminal registrado. |
| ERROR | Destinatário da requisição → emissor original | Obrigatório se a requisição já contém UUID; em erro de criação pode estar ausente ou identificar operação já persistida | Obrigatório | `{code, message, correlationId, retryable, details}`. |

Snapshot contém `{managerId, boleta, state, sequence}`. `reason` é obrigatório em REJECTED/SETTLEMENT_FAILED e proibido nos demais estados, inclusive no payload de REGISTER_OPERATION. `rejectionOrigin` é obrigatório em REJECTED (LOCAL ou CUSTODIAN) e proibido nos demais estados. Na resposta de criação, rejeição só pode ter origem LOCAL. Uma resposta ou consulta de rejeição local preserva a boleta recebida, inclusive financeiro inconsistente: valida sua representação estrutural sem exigir aprovação das regras de aceitação financeira/cadastral. O conteúdo não é corrigido pelo verificador. Os demais snapshots continuam sujeitos à validação completa da boleta.

`events` é obrigatório nas respostas de consulta da plataforma/custodiante; `deliveryStatus` e `reconciliationStatus` também são obrigatórios na consulta da plataforma. Os campos opcionais dos snapshots são limitados aos listados no schema. A projeção local e os eventos remotos têm sequências com escopos distintos, conforme [modelo de eventos](../domain/README.md); a validação integrada dos históricos/snapshots será especificada nos contratos REST. S1-11 verifica estrutura dos eventos, sem declarar coerência de um snapshot remoto com negócio persistido.

`details` é uma lista de objetos `{field, issue}`, strings não vazias até 256 caracteres. `message` tem o mesmo limite. `correlationId` repete o UUID de `requestMessageId`. Um erro de criação sem registro não inventa UUID de operação. Rejeição de domínio de operação persistida usa resultado de criação com UUID, estado REJECTED e motivo; erros técnicos não fazem o receptor inferir rejeição financeira. Ausência remota é `ERROR` com `code = NOT_FOUND`, assinada e correlacionada. As tasks de OpenAPI/SOAP definirão o mapeamento de códigos HTTP/Faults para estas mensagens.

Todas as respostas de negócio e erros após autenticação exigem assinaturas. Falhas de handshake/parsing podem não produzir envelope assinado; não autorizam avanço ou rejeição de estado remoto. O tipo de resposta deve corresponder ao tipo da requisição; emissor/destinatário são invertidos, ambiente/versão/operação são conferidos, e `requestMessageId` corresponde à requisição realmente enviada. A resposta tem seu próprio `messageId`.

## Perfis, política e validade

| Perfil | Lista ordenada de algoritmos em `signers` | Requisito |
|---|---|---|
| ECDSA | `ECDSA-P256-SHA256` | P-256, SHA-256, assinatura DER da biblioteca. |
| ML_DSA | `ML-DSA-65` | Modo puro, mensagem completa, contexto vazio, sem pré-hash próprio. |
| DUAL | `ECDSA-P256-SHA256`, depois `ML-DSA-65` | Ambas sobre os mesmos bytes, válidas e autorizadas; ausência/falha de uma rejeita tudo. |

Cada signatário é `{algorithm, keyId}`. `signatures` tem a mesma ordem e quantidade, cada entrada `{algorithm, keyId, value}`; algoritmo/chave devem corresponder exatamente aos valores protegidos. `value` usa Base64 padrão canônica, com padding quando necessário, sem quebras. O validador estrutural confere codificação e correspondência, não formato DER, tamanho ML-DSA ou validade criptográfica.

A política local vem da integração autenticada e limita identidades, ambiente, tipos de mensagem, versão e perfil. `policyVersion` recebido apenas referencia uma versão autorizada. Chaves são previamente registradas por participante/algoritmo/uso/validade/estado; não importar chave ou URL da mensagem. O verificador estrutural recebe um registro local ilustrativo: ACTIVE/VERIFY_ONLY podem verificar, REVOKED falha imediatamente, e a chave deve estar no intervalo de validade. O registro ilustrativo não contém material público real; autorização operacional/rotação persistida e criptografia continuam futuras.

Exigir `0 < expiresAt - issuedAt <= 120 s`, `issuedAt <= agora + 5 s` e `expiresAt >= agora - 5 s`. Relógio de segurança UTC é injetável, independente do financeiro. O corpus usa `2026-11-19T12:00:30Z`. Limites de entrada: 256 KiB UTF-8 do envelope, profundidade máxima 32 (raiz no nível 1), uma ou duas assinaturas conforme perfil. O parser isolado aplica tamanho antes de parsing e profundidade antes de qualquer verificação criptográfica; serviços futuros precisam limitar streaming/parser e conexões também.

## Identidade lógica e consultas

Criação usa `(managerId, clientOrderId)`, com a gestora autenticada como manager. Comandos de instrução/registro usam `(senderId, recipientId, messageType, operationId, instructionVersion)`. O digest de deduplicação será SHA-256 do negócio normalizado por JCS, incluindo referências operacionais e excluindo `messageId`, validade, assinatura e política. Isso não substitui assinatura nem autoriza deduplicar antes de autenticação/validade/autorização.

Uma reemissão pode renovar ID, validade, assinatura e política preservando identidade lógica e negócio. Conteúdo de negócio diferente para a mesma identidade é conflito. Resultado de comando idempotente conserva o negócio, mas ganha novo envelope de resposta, validade, correlação e política de saída atuais.

Consultas não são comandos de efeito e não usam essa chave para cachear snapshots: cada consulta nova usa `messageId` novo e lê o estado atual. Só repetição exata ainda válida pode receber resposta anterior. Resposta a consulta antiga não satisfaz consulta nova, mesmo para a mesma operação/versão. Não há armazenamento, cache ou garantia de frescor operacional implementados nesta task; o teste verifica correlação distinta.

## Verificação e limites da entrega

```powershell
$env:PATH = "C:\Users\Inteli\AppData\Local\Programs\DockerDesktop\resources\bin;$env:PATH"
$isolation = @('--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--mount',"type=bind,source=$((Get-Location).Path),target=/work,readonly",'-w','/work','-e','PYTHONDONTWRITEBYTECODE=1')
docker run @isolation cafi-events:s1 python -m unittest discover -s tests/contracts -p test_messages.py -v
docker run @isolation cafi-events:s1 python tests/contracts/check_messages_schema.py
docker run @isolation cafi-events:s1 python tests/contracts/check_messages_schema.py --invalid # saída 1 esperada
docker run @isolation cafi-spikes:s1 python tests/contracts/check_messages_schema.py # dependência ausente, saída 1 esperada
```

O ambiente `cafi-events:s1` é reproduzido pelo `deploy/contracts/Dockerfile` e dependências fixadas em `deploy/contracts/requirements-boleta.txt`; executar na raiz. [Evidência S1-11-C1](../../docs/sprint-1/evidence/messages.json) registra imagem, versões, hashes e resultados. O registry local resolve os URNs sem rede; o checker exige suporte efetivo a formatos, inclusive data impossível. Todos os 28 exemplos e requisições associadas são examinados; negativos de perfil, correspondência de signatários e relógio são rejeitados pelo validador contextual, não necessariamente pelo schema. Nenhum teste assina/verifica criptografia. O schema expressa estrutura e formatos; regras cruzadas de tipo, perfil, política, calendário e correlação são aplicadas explicitamente por `tests/contracts/validate_message.py`.

S1-15 corrigiu o exemplo `query_instruction_result`: histórico remoto começa em `RECEIVED`, sequência própria 1, com `previousState: SENT` para representar a transição financeira. O checker do custodiante valida continuidade e correspondência com snapshot. A evidência histórica S1-11 permanece inalterada e refere-se ao arquivo anterior. Não há serviço de negócio, transporte ou migração implementados.
