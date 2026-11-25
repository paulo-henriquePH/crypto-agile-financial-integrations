# S2-02 — corpo recebido → bytes canônicos → conteúdo verificado

Na raiz, com Git, PowerShell e Docker Linux `amd64` no `PATH`:

```powershell
# Apenas se a imagem da baseline ainda não existir:
docker build --platform linux/amd64 -f deploy/spikes/Dockerfile -t cafi-spikes:s1 .
docker build --platform linux/amd64 -f deploy/contracts/Dockerfile --target soap -t cafi-soap:s1 .

powershell -NoProfile -File spikes/s2-02/verify.ps1
```

O script usa o ID local da imagem e monta o checkout somente para leitura. A prova exige CPython 3.13.11, OpenSSL 3.5.9, `rfc8785` 0.1.4 e `lxml` 6.1.3. Os Dockerfiles da baseline fixam a imagem de origem, a fonte OpenSSL e os pacotes Python por hash. No Windows, se necessário, acrescente ao `PATH` do processo o diretório `resources\bin` da instalação do Docker Desktop.

`envelopes.py` não depende do runner, manifesto, corpus nem de `tests/`. Os adaptadores recebem o corpo bruto em bytes: `parse_json` usa `json` com detecção de duplicatas e JCS; `parse_xml` usa preflight Expat e uma árvore `lxml` validada por `soap_schema(contracts)`, com imports locais permitidos. O caminho de `Fault/Detail` também é exercitado. `receive` recebe o parser, o binding, o perfil e as chaves públicas esperadas pelo chamador. Só depois de todas as verificações chama `consume` com a região assinada. O consumidor XML deve ler todos os segmentos de texto de um campo (`text`), inclusive quando separados por comentários.

`proof.py` reutiliza o binding EVP `tests/contracts/signed_crypto.py`: ECDSA P-256/SHA-256 em DER e ML-DSA-65 puro, mensagem completa, contexto vazio. Compara os bytes com as referências congeladas e verifica o corpus apenas com SPKI. Reassina seis requisições com chaves efêmeras em memória, recoloca as assinaturas no corpo de transporte e verifica esses bytes pelo mesmo receptor. No XML, a prova observa a chamada real de C14N e a árvore da validação XSD e exige identidade (`is`) com o objeto recebido pelo consumidor. Divergência, aceitação de negativo ou falha operacional encerra com erro.

**Limite:** este é o candidato ao processamento dos corpos, não um endpoint. Esquemas REST por rota, correspondência entre ação/tipo, relógio, correlação, identidade do par e autorização completa pertencem à integração C1. S2-03 ainda precisa demonstrar o transporte e preservar os corpos brutos; mudança de runtime, parser ou binding exige repetir as provas afetadas.

[Saída sanitizada da execução](../../docs/sprint-2/evidence/s2-02.json). `baseRevision` é a base aprovada de S2-01; **esse commit não contém S2-02**. Na reprodução pré-commit, `checkoutRevision` ainda aponta para a base: o diretório executado foi exportado de um índice temporário contendo a base mais os seis arquivos da proposta. `sourcesSHA256` identifica os bytes efetivamente executados de `proof.py` e `envelopes.py`; `.gitattributes` fixa LF nos dois arquivos inclusive com `core.autocrlf=true`.

Após o commit, faça checkout limpo **do commit que contém S2-02**, execute o comando acima e compare `sourcesSHA256`, as versões e os resultados por caso com a evidência. `checkoutRevision` então identificará o commit da entrega. Para conferir os bytes de forma independente: `Get-FileHash spikes/s2-02/*.py -Algorithm SHA256`.
