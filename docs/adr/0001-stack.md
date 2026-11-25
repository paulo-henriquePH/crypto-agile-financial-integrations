# ADR 0001 — Stack de referência para viabilidade criptográfica

**Status:** decisão S1-08: caminho criptográfico viável no laboratório; stack de serviços ainda não aprovada.

**Data:** 2026-11-24. **Base revisada:** `26a5d93be49afc2da5d27b875974aa7c8c5de6a2` (`sprint-1-completion`).

## Contexto e decisão

A [SPEC §2](../../SPEC.md#2-arquitetura-e-execução) exige que o runtime faça as operações reais e que o cliente e o servidor controlem e observem o grupo TLS efetivamente negociado. A [S1-08](../SPRINT-1.md#s1-08-registrar-a-decisão-da-stack) decide o caminho comprovado antes dos conectores; a [semana 1](../../README.md#plano-de-desenvolvimento) e o [escopo da sprint](../sprint-1/scope.md) também exigem contratos e vetores, que não são substituídos por essas provas.

Adotar **Python / CPython 3.13.11 em Linux `amd64`**, com **`ctypes` da biblioteca padrão dessa versão** e **OpenSSL 3.5.9** (`libcrypto.so.3` para EVP, `libssl.so.3` para TLS) como referência reproduzível das provas e ponto de partida para os adaptadores. É o caminho que executou os dois algoritmos de mensagem e os dois grupos, sem primitivas próprias e sem subprocesso por assinatura ou handshake. O [manifesto](../../deploy/spikes/versions.json) fixa a imagem Python Debian Bookworm por digest, a fonte OpenSSL por SHA-256 e não inclui pacotes Python de terceiros. As bibliotecas carregadas do prefixo `/opt/cafi-openssl` e seus hashes estão no diagnóstico e nas provas, não são inferidas do OpenSSL do host. O [build](../../deploy/spikes/Dockerfile) ativa o provider `default`, confirmado na prova ML-DSA; parâmetros e tamanhos conferidos contra FIPS 204 não constituem certificação do provider ou da stack. O pin de laboratório, inclusive a versão Python já sucedida, não é recomendação de segurança para produção.

**Terminação TLS:** direta nos processos dos pares, via OpenSSL, sem proxy/sidecar no caminho de referência. Na prova, os dois papéis rodam no mesmo processo Python, com contextos e sockets distintos sobre TCP loopback. Para os serviços, testar a mesma terminação no adaptador `transport` de cada participante, em processos separados; isso é a direção preferida, não uma integração já validada. A conexão só é aceita com o grupo exigido, verificado no objeto TLS do próprio par, nunca por cabeçalho do cliente. Não se introduz trecho interno nem nova fronteira de confiança. Se um terminador separado se mostrar necessário, será outra decisão: atualizar o [modelo de ameaças](../security/threat-model.md#ativos-atores-e-confiança), proteger o trecho interno e a propagação autenticada de identidade/metadados e medir o custo adicional, conforme a SPEC.

Em ambos os grupos, a autenticação TLS é **tradicional** (certificados EC P-256 assinados com SHA-256, `ecdsa_secp256r1_sha256` como única assinatura de handshake permitida). X25519MLKEM768 muda o estabelecimento de chaves, não a autenticação do canal. **ML-DSA-65 autentica a mensagem**, com chave distinta da de TLS. mTLS não substitui vincular o par a `senderId` e autorizar carteira e ação. A plataforma continua uma fronteira explícita: assina como plataforma nos conectores, preservando `managerId`, sem alegar assinatura da gestora ponta a ponta.

## Matriz de suporte observado

Os IDs abaixo remetem aos comandos de reprodução. Em TLS, ACK significa uma confirmação de um byte cifrada, não uma requisição HTTP/SOAP.

| Componente | Caminho realmente executado | Resultado observado | Comando / evidência |
|---|---|---|---|
| Runtime e binding | `ctypes.CDLL` por caminho absoluto; `OpenSSL_version`, `EVP_SIGNATURE_fetch` e resolução de símbolos | Python/OpenSSL efetivamente carregados, implementações ECDSA e ML-DSA-65 disponíveis para consulta; inventário sem geração de chave, assinatura ou handshake. | D · [S1-03](../../deploy/spikes/diagnostic-2026-11-24.json) |
| ECDSA P-256/SHA-256 (`libcrypto`) | Geração via `EVP_PKEY_generate`; `EVP_DigestSignInit_ex`/`EVP_DigestSign` e `EVP_DigestVerifyInit_ex`/`EVP_DigestVerify` via `ctypes` | ASN.1 DER, não `r \|\| s`; original aceito, payload/assinatura alterados e outra chave rejeitados. | E · [S1-04](../sprint-1/evidence/ecdsa.json) |
| ML-DSA-65 (`libcrypto`) | `EVP_PKEY_generate`; `EVP_PKEY_sign_message_init`/`EVP_PKEY_sign` e `EVP_PKEY_verify_message_init`/`EVP_PKEY_verify` via `ctypes` | Modo puro, mensagem completa com comprimento explícito, contexto vazio (`message-encoding=1`, `mu=0`), sem pré-hash próprio. Original aceito; payload/assinatura alterados, outra chave pública e contexto diferente rejeitados. Assinatura: 3309 B brutos / 4412 caracteres Base64; chave pública: 1952 B brutos / 1974 B SPKI DER / 2726 B SPKI PEM. | M · [S1-05](../sprint-1/evidence/ml-dsa.json) |
| Cliente TLS (`libssl`) | `SSL_connect` e `SSL_read_ex` via `ctypes` | mTLS 1.3 e ACK com X25519 e X25519MLKEM768; rejeita cadeia não confiável e SAN errado no servidor. Cliente só X25519 recebe alerta fatal diante de servidor só híbrido. | T/H · [S1-06](../sprint-1/evidence/tls-x25519.json), [S1-07](../sprint-1/evidence/tls-hybrid.json) |
| Servidor TLS candidato (`libssl`) | Listener mínimo em Python, `SSL_accept` e `SSL_write_ex` via `ctypes` | mTLS 1.3 e ACK nos dois grupos; rejeita certificado de cliente ausente, CA não confiável e SAN errado. Servidor só híbrido rejeita cliente só X25519 (`no suitable key share`, sem ACK/fallback). | T/H · [S1-06](../sprint-1/evidence/tls-x25519.json), [S1-07](../sprint-1/evidence/tls-hybrid.json) |
| Binding TLS: política e observação | `SSL_CTX_ctrl` (`SSL_CTRL_SET_GROUPS_LIST`) limita a um grupo; `SSL_get0_group_name` consulta ambos os objetos `SSL` vivos | `x25519` no cenário tradicional e `X25519MLKEM768` no híbrido nas duas pontas; símbolo ausente, `NULL` ou divergência falham, sem usar configuração como evidência. `SSL_get_version` e `SSL_get_current_cipher`/`SSL_CIPHER_get_name` confirmam `TLSv1.3` e `TLS_AES_256_GCM_SHA384` em ambos. | T/H · [S1-06](../sprint-1/evidence/tls-x25519.json), [S1-07](../sprint-1/evidence/tls-hybrid.json) |
| TLS: identidade e certificado | `SSL_set1_host`, `SSL_get0_peername`, `SSL_get_verify_result`, `SSL_get0_verified_chain` e `SSL_get0_peer_certificate`; `X509_get0_pubkey`, `EVP_PKEY_get0_type_name`/`EVP_PKEY_get_group_name` e `X509_get_signature_nid`/`OBJ_nid2sn` | Cadeia da CA de laboratório e SAN DNS exato (sem wildcard/CN), chave EC P-256 e assinatura do certificado ECDSA/SHA-256 observados nos dois grupos. | T/H · [S1-06](../sprint-1/evidence/tls-x25519.json), [S1-07](../sprint-1/evidence/tls-hybrid.json) |
| TLS: controles de sessão | `SSL_session_reused`, `SSL_SESSION_has_ticket`/`SSL_SESSION_is_resumable` e `SSL_get_early_data_status` | Cache/tickets e 0-RTT desabilitados; ausência de retomada, ticket ou early data nas duas conexões positivas por execução, com reuso de `SSL_CTX`, não de socket ou `SSL`. | T/H · [S1-06](../sprint-1/evidence/tls-x25519.json), [S1-07](../sprint-1/evidence/tls-hybrid.json) |
| OpenSSL CLI | `openssl req`/`x509` no [gerador de certificados](../../spikes/tls/certificates.py) | Só PKI efêmera no tmpfs; não executa handshake, não observa grupo e não assina a mensagem de negócio. | T/H · [S1-06](../sprint-1/evidence/tls-x25519.json), [S1-07](../sprint-1/evidence/tls-hybrid.json) |

## Proveniência e reprodução

| Comando | `baseRevision` gravada | Commit que incorpora prova e evidência |
|---|---|---|
| D (build/inventário) | `73e3197c0dd1f3763367233663d9a3856dc13fa0` | `799aa87bb182057cd0e359f61e464e3fa471a269` |
| E (ECDSA) | `799aa87bb182057cd0e359f61e464e3fa471a269` | `000b959f0320a3b4841862fe7c80ac50969e4514` |
| M (ML-DSA) | `000b959f0320a3b4841862fe7c80ac50969e4514` | `0999a7d4ed781f5a9c2604fa39f0b7c2da0b5ab1` |
| T (X25519 histórico) | `0999a7d4ed781f5a9c2604fa39f0b7c2da0b5ab1` | `e577027025747307d7e3b84e84aaab6d5b013e33` |
| H e regressão T (harness atualizado) | `e577027025747307d7e3b84e84aaab6d5b013e33` | `26a5d93be49afc2da5d27b875974aa7c8c5de6a2` |

A revisão-base antecede a alteração da respectiva task: `inputsSHA256` nos JSON identifica os bytes usados, inclusive o harness TLS diferente em S1-06 e S1-07. Para comparar hashes históricos, usar a revisão correspondente e considerar a conversão de finais de linha do checkout; o hash registrado é dos bytes efetivos, não do texto normalizado. Na base desta ADR, T reproduz a regressão de S1-07; para o harness histórico de T, usar os arquivos de S1-06.

Comandos PowerShell na raiz, seguindo o [roteiro isolado](../../spikes/README.md#reprodução) (inclui Linux e ajuste de PATH só do processo no Windows). Reutilizar `cafi-spikes:s1` quando já disponível; o build D é para preparar a imagem se necessário.

```powershell
# D — build e inventário; registre a revisão dos arquivos de entrada
docker build --platform linux/amd64 --no-cache -f deploy/spikes/Dockerfile -t cafi-spikes:s1 .
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges -e "CAFI_CODE_REVISION=$(git rev-parse HEAD)" cafi-spikes:s1
# E — ECDSA
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --mount "type=bind,source=$((Get-Location).Path)\spikes\signatures\ecdsa,target=/proof,readonly" cafi-spikes:s1 python /proof/proof.py
# M — ML-DSA
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --mount "type=bind,source=$((Get-Location).Path)\spikes\signatures\ml-dsa,target=/proof,readonly" cafi-spikes:s1 python /proof/proof.py
# T — X25519
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 65534:65534 --tmpfs /tmp:rw,noexec,nosuid,nodev,size=1m,mode=0700,uid=65534,gid=65534 --mount "type=bind,source=$((Get-Location).Path)\spikes\tls,target=/proof,readonly" cafi-spikes:s1 python /proof/proof.py
# H — X25519MLKEM768; executar duas vezes, em invocações separadas
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 65534:65534 --tmpfs /tmp:rw,noexec,nosuid,nodev,size=1m,mode=0700,uid=65534,gid=65534 --mount "type=bind,source=$((Get-Location).Path)\spikes\tls,target=/proof,readonly" cafi-spikes:s1 python /proof/proof.py --hybrid
```

Os relatórios registram saída 0 nos cenários normais, incluindo as rejeições esperadas, regressão T e duas invocações H com processo, PKI e conexões novos. A perturbação do caso positivo (`--corrupt-original` em E/M, `--wrong-positive-name` em T/H) saiu com 1; M e T também registram falha por biblioteca ausente. Chaves de mensagem são geradas em memória; chaves TLS são efêmeras no tmpfs. Repetir exige resultados equivalentes, não chaves ou assinaturas idênticas. A ADR usa as evidências commitadas, sem declarar nova execução.

## Limites, alternativas e próximos gates

- **Binding:** `ctypes` prova acesso às APIs públicas, não é adaptador pronto. Tipos C explícitos (`argtypes`/`restype`, ponteiros e `size_t`), layout de `OSSL_PARAM`, comprimentos binários e macros/constantes dos headers devem corresponder à ABI fixada. Erros podem causar truncamento, corrupção ou falha de processo. Isolar a interface de `crypto`/`transport`; revisar ownership e tempo de vida (inclusive ponteiros emprestados `get0`), liberar contextos/chaves/objetos TLS também em falhas, tratar códigos de retorno e fila de erros na thread da chamada e exercitar I/O parcial, timeout, concorrência e vazamentos antes dos conectores. Binding mantido ou extensão compilada com os headers é alternativa, não suporte demonstrado: repetir as provas antes de trocar.
- **Servidores e clientes candidatos:** o listener mínimo é a única referência exercitada; não é servidor HTTP. Para REST e o transporte HTTP do SOAP, avaliar um servidor Python com integração direta ao adaptador TLS ou um servidor ASGI candidato (por exemplo, Uvicorn ou Hypercorn), e clientes que exponham o transporte necessário. Nem esses servidores, o módulo `ssl` de Python, nem cliente SOAP foram exercitados como caminho TLS; não há versão de framework/cliente selecionada. Antes de escolher e fixar versões, reproduzir os dois grupos nos clientes e listeners reais, em processos separados, com mTLS, identidade ligada à política, grupo observado sem fallback e controles de sessão sob as configurações da SPEC. Ao selecionar a stack de serviços, registrar nesta ADR a linguagem, o runtime, os frameworks, clientes, servidores e bibliotecas escolhidos, com suas versões, o mecanismo de observação do grupo negociado e os comandos das provas correspondentes. Não há evidência de interoperabilidade com outra implementação, injeção ativa de PSK/0-RTT, revogação ou migração.
- **Ferramentas da S1-09:** usar o CPython fixado como alvo, com `json` (detecção de duplicatas antes das regras estruturais), `decimal.Decimal`/`ROUND_HALF_UP`, `datetime` e `unittest` da biblioteca padrão para o [validador isolado da boleta](../../contracts/schemas/README.md), sem banco, servidor, dependência flutuante ou `float` financeiro. Isso não substitui a validação independente do schema. Na revisão S1-08, a revalidação dos modelos no runtime fixado e a seleção do motor de schema para as verificações de laboratório ainda estavam pendentes; veja a consolidação abaixo.

## Consolidação após a verificação final da Sprint 1

A [execução final](../sprint-1/evidence/final-verification.json), em checkout limpo de `d715c2c2980b34ddab6fe62322a6f5f569e669b1`, ampliou as provas da revisão S1-08 sem alterar a decisão de stack. No ambiente fixado Linux `amd64`, passou sem skips e verificou os modelos e contratos, JCS (`rfc8785` 0.1.4) e Exclusive XML C14N 1.0 (`lxml` 6.1.3) contra bytes de referência congelados. Verificou também [vetores assinados JSON/XML](../../contracts/vectors/signed/), estáticos e recém-gerados, nos três perfis, e voltou a observar ambos os grupos TLS em cliente e servidor do harness. As referências independentes JavaScript e .NET não foram reexecutadas pelo runner final. A validação XSD/WSDL e o carregamento por Zeep 4.3.2 foram offline: não houve chamada SOAP nem teste do transporte desse cliente.

O [índice da Sprint 1](../sprint-1/README.md#reprodução-e-evidência) reúne a reprodução e os pré-requisitos do comando `powershell -NoProfile -File scripts/verify-sprint1/verify.ps1`. As bibliotecas usadas no verificador não são, por isso, escolhas aprovadas para os serviços.

**Gate ainda pendente:** verificar assinatura e canonicalização interoperável com os parsers escolhidos, garantindo que o mesmo nó XML verificado seja processado, e demonstrar mTLS com o grupo exigido nos clientes e servidores REST/SOAP reais, conforme a [SPEC §2](../../SPEC.md#2-arquitetura-e-execução). As provas não validam endpoints, persistência, C1–C6 nos adaptadores nem T01–T14 completos. Dependência indispensável ausente ou prova obrigatória falhando bloqueia o gate; não reduzir proteções para integrar.
