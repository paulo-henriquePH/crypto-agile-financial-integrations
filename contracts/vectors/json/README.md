# Vetores JCS — S1-12

Os arquivos `*.input.json` são entradas e `*.canonical` contêm bytes UTF-8 exatos, sem BOM ou quebra final. [manifest.json](manifest.json) associa modo, resultado esperado, arquivo canônico e SHA-256 de conferência. `.gitattributes` impede conversão de finais de linha nos bytes esperados. Nenhuma assinatura criptográfica é produzida nesta task.

## Biblioteca e expectativa independente

O executor [canonical_json.py](../../../tests/contracts/canonical_json.py) usa **rfc8785 0.1.4**, da Trail of Bits, fixado por versão e hash do wheel em [requirements.txt](requirements.txt). Fontes oficiais consultadas em 2026-11-19: [metadados PyPI](https://pypi.org/pypi/rfc8785/0.1.4/json) e [repositório do autor](https://github.com/trailofbits/rfc8785.py).

Os bytes esperados foram produzidos separadamente por **canonicalize 5.1.0**, biblioteca JavaScript de Samuel Erdtman, usando Node 22.14.0. O [lockfile](reference/package-lock.json) fixa integridade SHA-512 e URL do pacote; [fonte oficial](https://github.com/erdtman/canonicalize) e [metadados do release](https://registry.npmjs.org/canonicalize/5.1.0) foram consultados. A função Python sob teste não foi usada para gerar expectativas. `reference/check.mjs` compara a segunda implementação com os arquivos congelados sem modificá-los; `--write-expectations` é apenas ferramenta explícita de autoria, não faz parte da verificação normal.

Dois casos reproduzem dados e regras da [RFC 8785 §§3.2.2–3.2.3](https://www.rfc-editor.org/rfc/rfc8785.html#section-3.2.3): serialização de primitivas e ordem de propriedades UTF-16. A expectativa do primeiro foi também conferida com a linha canônica publicada; a ordem do segundo corresponde à sequência publicada (CR, `1`, controle U+0080, ö, €, emoji, letra hebraica). Outro caso preserva diferenças entre caracteres compostos/decompostos e cobre escapes/objetos dentro de arrays.

## Escopo do conteúdo

Os dois vetores de criação derivam do exemplo estrutural S1-11 e têm ordens/indentação diferentes, mas resultam nos mesmos 906 bytes e digest. O modo `envelope` assina exclusivamente `{protected, payload}`: a lista `protected.signers` permanece incluída e `signatures` fica excluída. Um teste altera assinatura externa e confirma bytes iguais; trocar `keyId` protegido muda os bytes. Valores de assinatura de entrada continuam ilustrativos.

O parser rejeita duplicatas, inclusive nomes equivalentes após unescape, antes de chamar JCS. Valores financeiros ficam strings; trocar `grossAmount` por número falha. Há negativos de payload com tipo errado, NaN, infinito e Unicode inválido. Tipos Python que não pertencem a JSON e inteiros fora do intervalo suportado pela biblioteca também falham. A biblioteca limita inteiros Python a ±(2^53−1); quantias financeiras usam strings, portanto não passam por arredondamento IEEE 754.

O modo `document` testa JCS genérico e admite `null`, como a RFC; o modo `envelope` aplica as restrições de contêiner, nulos, tamanho e profundidade do perfil da aplicação. Canonicalização não autentica, autoriza nem valida todos os campos de uma mensagem: o validador S1-11 e a futura verificação de assinaturas continuam necessários. O conferidor JavaScript usa `JSON.parse` apenas nos vetores positivos conhecidos, não prova rejeição de duplicatas; esse controle é testado pelo parser Python antes da canonicalização.

## Reprodução sem build

PowerShell, na raiz do repositório, usando ambientes temporários fora do Git:

```powershell
py -3 -m venv "$env:TEMP/cafi-s1-jcs-venv"
& "$env:TEMP/cafi-s1-jcs-venv/Scripts/python.exe" -m pip install --require-hashes --only-binary=:all: -r contracts/vectors/json/requirements.txt
& "$env:TEMP/cafi-s1-jcs-venv/Scripts/python.exe" -m unittest discover -s tests/contracts -p test_canonical_json.py -v
New-Item -ItemType Directory -Force "$env:TEMP/cafi-s1-jcs-reference" | Out-Null
Copy-Item contracts/vectors/json/reference/package*.json "$env:TEMP/cafi-s1-jcs-reference/"
npm.cmd ci --prefix "$env:TEMP/cafi-s1-jcs-reference" --ignore-scripts
node contracts/vectors/json/reference/check.mjs "$env:TEMP/cafi-s1-jcs-reference/node_modules/canonicalize/lib/canonicalize.js"
```

Em Linux, use `python3 -m venv /tmp/cafi-s1-jcs-venv`, o Python em `bin/python`, `npm` e caminhos equivalentes. O comando Python exige dependência presente e versão exata; indisponibilidade não produz skip. A comparação independente requer Node >=22, conforme o pacote fixado; execução observada em Node 22.14.0. Não é necessário compilar dependências, iniciar Docker ou escolher a stack final.

Resultado observado em Python 3.12.0/Windows: cinco métodos de teste aprovados, 12 casos no manifesto (cinco positivos e sete negativos), cinco comparações JavaScript aprovadas. O limite de 256 KiB é aplicado antes de qualquer parsing; um teste com spies confirma que nenhum dos dois parsers é chamado para entrada excessiva. Hashes e arquivos congelados são a evidência reproduzível; [evidence.json](evidence.json) registra ambiente e comandos. S1-03–08 permanecem pendentes: este resultado comprova canonicalização local, não Linux fixado, assinaturas ou TLS.

## Revalidação S1-12-C1 em Linux

O parágrafo anterior descreve exclusivamente a execução histórica; S1-03–08 foram realizados posteriormente. A execução em CPython 3.13.11 está em [jcs.json](../../../docs/sprint-1/evidence/jcs.json). Na raiz, com Docker disponível, construir `docker build -f deploy/contracts/Dockerfile -t cafi-jcs:s1 .` e executar, substituindo `<repo>` pelo caminho absoluto:

```text
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --mount type=bind,source=<repo>,target=/work,readonly -w /work -e PYTHONDONTWRITEBYTECODE=1 cafi-jcs:s1 python -m unittest discover -s tests/contracts -p test_canonical_json.py -v
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --mount type=bind,source=<repo>,target=/work,readonly -w /work -e PYTHONDONTWRITEBYTECODE=1 cafi-jcs:s1 python -m unittest discover -s tests/contracts -v
```

A imagem instala o wheel fixado com verificação de hash e mantém as dependências de schema. As comparações independentes JavaScript são evidência histórica, não foram reexecutadas nesta revalidação; os bytes congelados e hashes foram verificados pelo executor Python. Assinaturas continuam ilustrativas.
