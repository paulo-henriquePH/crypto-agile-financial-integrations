# Vetores assinados — S1-17

Este corpus contém **27 mensagens e 36 assinaturas reais**. Os exemplos
históricos em `contracts/messages/`, `contracts/openapi/`, `contracts/soap/`
e nas suítes de canonicalização continuam **ilustrativos**; não são aceitos
como assinaturas reais. Cada linha abaixo cobre os três perfis (`ECDSA`,
`ML_DSA`, `DUAL`) e três papéis (requisição, resposta, erro):

| Integração | Requisição | Resposta | Erro alternativo correlacionado à mesma requisição |
|---|---|---|---|
| Plataforma REST/JSON | `POST /v1/operations` | `201 CREATE_OPERATION_RESULT` | `409 ERROR` |
| Custodiante REST/JSON | `POST /v1/instructions` | `202 SUBMIT_INSTRUCTION_RESULT` | `409 ERROR` |
| Administrador SOAP 1.2/XML | `RegisterOperation` | `REGISTER_OPERATION_RESULT` | `Fault/Detail/Message` com `ERROR` |

Os erros assinados representam `IDEMPOTENCY_CONFLICT` em cenários
alternativos, não uma segunda resposta no cenário de sucesso nem uma
rejeição financeira. O verificador recebe o perfil, a direção e a rota/ação
da configuração de teste. O `Reason` e o `Code` externos do SOAP Fault não
são usados como erro de negócio. Os exemplos incluem a boleta e o snapshot dos
contratos aprovados; o recibo do custodiante não implica aceitação financeira.

- [`corpus/manifest.json`](corpus/manifest.json) associa cada mensagem aos
  bytes assinados (`*.canonical.b64`, Base64 padrão dos bytes exatos), ao
  SHA-256 desses **bytes decodificados**, à requisição correspondente e à
  expectativa `accepted`. As assinaturas ficam no envelope, não no arquivo de
  bytes canônicos. O relógio injetado é `2026-11-19T12:00:30Z`; os vetores
  estão expirados fora da janela declarada, independentemente do relógio atual.
- [`corpus/trust.json`](corpus/trust.json) é a configuração local e separada
  de confiança, com chaves **públicas** SPKI DER em Base64, selecionadas pela
  tupla `(participante, algoritmo, keyId)` e autorizadas por estado e vigência.
  Nenhuma mensagem pode introduzir ou substituir essa configuração. Para um
  corpus regenerado, passe o novo registro explicitamente com `--trust`.
- JSON usa JCS sobre `{protected, payload}` após rejeitar propriedades
  duplicadas. XML valida o envelope SOAP/XSD pelo caminho aprovado,
  canonicaliza `SignedContent` com Exclusive C14N 1.0 sem comentários e lê
  os dados do mesmo nó, sem remover whitespace. `algorithm` e `keyId` são
  assinados dentro de `protected`/`Protected`; a lista externa precisa
  corresponder à lista assinada.
- ECDSA usa `EVP_DigestSign`/`EVP_DigestVerify`, P-256/SHA-256 e DER.
  ML-DSA-65 usa as APIs EVP de mensagem inteira, modo puro, contexto vazio
  (`message-encoding=1`, `mu=0`). DUAL exige as duas assinaturas autorizadas
  sobre os mesmos bytes; a remoção ou troca de qualquer uma rejeita o todo.
  Não há subprocesso por assinatura.
- A decisão EVP separa `0` (assinatura inválida) de falha operacional,
  que aborta com saída 1 e informa os códigos da fila OpenSSL sem dados do
  envelope. No OpenSSL 3.5.9 fixado, `-1` de ECDSA com fila vazia só conta
  como assinatura inválida quando o decodificador DER da biblioteca confirma
  formato inválido/não canônico. `-2`, ou `-1` com DER válido, são falhas
  operacionais, não rejeições esperadas dos vetores negativos.
- O gerador mantém as privadas apenas em objetos EVP na memória do processo e
  libera esses objetos antes de escrever arquivos; só exporta o SPKI público.
  Não monte uma pasta de saída do Git. A regeneração usa novas chaves e não
  precisa produzir assinaturas iguais; cada corpus deve passar com o seu
  registro público.

## Reprodução

PowerShell na raiz, com Docker disponível. Se necessário, montar a imagem
local com `docker build --platform linux/amd64 --target soap -f deploy/contracts/Dockerfile -t cafi-soap:s1 .`
usando a base `cafi-spikes:s1` do [ambiente fixado](../../../deploy/spikes/versions.json).

```powershell
$env:PATH = "C:\Users\Inteli\AppData\Local\Programs\DockerDesktop\resources\bin;$env:PATH"
$iso = @('--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--mount',"type=bind,source=$((Get-Location).Path),target=/work,readonly",'-w','/work','-e','PYTHONDONTWRITEBYTECODE=1')
docker run @iso cafi-soap:s1 python tests/contracts/verify_signed_vectors.py
docker run @iso cafi-soap:s1 python -m unittest discover -s tests/contracts -v
docker run @iso cafi-soap:s1 python tests/contracts/verify_signed_vectors.py --invalid # saída 1: adulteração chega ao EVP
docker run @iso cafi-spikes:s1 python tests/contracts/verify_signed_vectors.py # saída 1: falta rfc8785

# Crie uma pasta de saída aprovada e separada do repositório.
$out = Join-Path $env:LOCALAPPDATA "Temp\opencode\cafi-s1-17-$([guid]::NewGuid())"
New-Item -ItemType Directory -Path $out | Out-Null
docker run @iso --mount "type=bind,source=$out,target=/out" cafi-soap:s1 python contracts/vectors/signed/generate.py --out /out/fresh
docker run @iso --mount "type=bind,source=$out,target=/out,readonly" cafi-soap:s1 python tests/contracts/verify_signed_vectors.py --corpus /out/fresh --trust /out/fresh/trust.json
docker run @iso --mount "type=bind,source=$out,target=/out,readonly" -e 'CAFI_SIGNED_TEST_CORPUS=/out/fresh' cafi-soap:s1 python -m unittest discover -s tests/contracts -p test_signed_vectors.py -v
```

Os negativos executam o verificador real, sem comparar primeiro com o digest
congelado: adulteração válida de payload/contexto, troca/remoção de assinatura
e chave pública incorreta, inclusive para cada algoritmo em DUAL. Também
testam política, revogação, expiração, correlação, duplicatas JSON, wrapping,
XXE, XInclude e whitespace XML. A [evidência](../../../docs/sprint-1/evidence/signed-vectors.json)
registra as versões, hashes e resultados. Trata-se de verificação isolada do
contrato, não de serviço, autenticação mTLS, migração, persistência, resistência
a replay operacional, certificação criptográfica ou prova de interoperabilidade
das assinaturas com uma segunda implementação.
