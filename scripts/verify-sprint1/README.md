# Verificação integrada — Sprint 1

Em checkout confiável, com Git, Windows PowerShell 5.1 ou PowerShell 7 e Docker
Engine em modo Linux (`linux/amd64`), execute na raiz:

```powershell
powershell -NoProfile -File scripts/verify-sprint1/verify.ps1
```

Em Windows com política de execução restritiva, autorize somente o processo
com `-ExecutionPolicy Bypass` antes de `-File`. Em Linux o mesmo script pode
ser invocado com `pwsh` no lugar de `powershell`; a execução registrada nesta
task é Windows/Docker Desktop. O runner procura Docker no PATH, com fallback
para a instalação por usuário do Docker Desktop em `%LOCALAPPDATA%`.

Não exige imagens de projeto locais, Python/pip no host ou serviços externos
em runtime. O build precisa acessar a imagem base fixada por digest, o release
OpenSSL com checksum SHA-256 e os wheels PyPI fixados por versão e hash.
Os **dois** builds normais usam `--no-cache`; o OpenSSL pode levar minutos.
A imagem de contratos usa a tag exclusiva da base desta execução, cuja
identidade é conferida antes e depois, e as camadas da imagem base são
conferidas na imagem final. Os contêineres são executados somente por ID,
sem pull. Nenhuma imagem/cache preexistente é removida.

O runner copia os bytes do checkout para um snapshot temporário dos artefatos
versionados (mais os quatro arquivos deste runner, inclusive antes do primeiro
commit); build e runtime leem a mesma projeção. O relatório distingue HEAD
da árvore com alterações e registra SHA-256 dos bytes realmente copiados.
O SHA-256 do snapshot resume as linhas UTF-8 `caminho sha256\n`, em ordem
ordinal de caminho, com separador `/` e finais LF.
O snapshot é montado somente leitura. Todos os contêineres rodam sem rede
externa, sem root, sem capabilities, sem privilégios adicionais e com
filesystem principal somente leitura. O corpus novo fica exclusivamente em
tmpfs; privadas de assinatura permanecem em memória. Cada execução TLS usa
um contêiner/processo/PKI próprio com tmpfs privado de 1 MiB; não há portas
publicadas nem material privado exportado.

O comando verifica os schemas e exemplos de boleta, eventos e mensagens,
OpenAPI da plataforma e do custodiante, WSDL/XSD/Zeep, 69 métodos de teste
sem skips, os vetores JCS e XML, os 27 vetores de assinatura estáticos e a
geração/verificação separada de 27 novos vetores, com 15 métodos adicionais
para seus negativos. Executa também as provas ECDSA e ML-DSA, TLS X25519 e
duas invocações TLS X25519MLKEM768, com grupos observados nas duas pontas,
mTLS e negativos, inclusive o cliente X25519 incompatível. Resultados
históricos de referência independente (JavaScript e .NET) **não são
reexecutados nem contados**. Não se valida serviço, interoperabilidade de
conectores, migração ou benchmark. Não há integração CI declarada.

Contraprova, depois da execução normal:

```powershell
powershell -NoProfile -File scripts/verify-sprint1/verify.ps1 -SelfTestInvalid
```

Esse modo constrói suas próprias tags (permite cache de camadas), verifica
primeiro o corpus estático intacto e então passa `--invalid` ao mesmo
verificador. O caso positivo recebe em memória uma boleta bem-formada com
payload alterado; a assinatura deve falhar no EVP antes da comparação de
bytes/digest. O runner propaga **exit 1** e grava a causa
`mutated-expected-positive-rejected-by-EVP`. Outro erro não demonstra a
contraprova. Não há alteração da fixture no checkout ou na imagem.

Cada invocação grava um JSON sanitizado distinto em
`.spikes/verify-sprint1/` (ignorado pelo Git): revisão-base, hashes de entrada,
pins, IDs/camadas das imagens, versões efetivas, comandos, códigos, casos,
falhas e skips. O console exibe etapas e caminho relativo; stdout/stderr
brutos, chaves, certificados e conteúdo das mensagens não são publicados.
Código 0 exige todas as etapas obrigatórias; erros interrompem a execução,
e casos não atingidos não são contados. Selecione explicitamente o resumo
sanitizado para `docs/sprint-1/evidence/integrated.json`. O gate S1-19 deve
reexecutar o comando normal sobre o commit aprovado de S1-18, registrando
o hash desse commit — uma execução anterior ao commit não o substitui.
