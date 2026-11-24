# Ambiente das provas isoladas

**Execução atual:** o build sem cache e o diagnóstico isolado terminaram com sucesso; versões carregadas, comandos e limites constam da [evidência sanitizada](../deploy/spikes/diagnostic-2026-11-24.json), sujeita a revisão independente. A [primeira tentativa histórica](../deploy/spikes/diagnostic-blocked.json) falhou no linker quando o disco físico C: tinha aproximadamente 123 MiB livres; esse registro permanece preservado. Não foi usado prune global nem removido dado alheio ao trabalho.

S1-03 prepara um candidato: CPython 3.13.11 com `ctypes` da biblioteca padrão chamando diretamente as bibliotecas compartilhadas OpenSSL 3.5.9. Não há subprocesso por assinatura nem implementação própria de primitivas. A stack só será decidida em S1-08, após as provas S1-04–07. O binding é de baixo nível e requer declarações corretas de tipos e gestão de recursos; não é um adapter de produção.

## Reprodução

Requer Docker Engine em modo Linux, acesso à imagem oficial e ao release OpenSSL no GitHub. No Windows, Docker Desktop com WSL2 foi usado. Execute na raiz do repositório, em PowerShell ou shell Linux:

No Windows, caso o helper `docker-credential-desktop` não seja encontrado, acrescente `C:\Users\Inteli\AppData\Local\Programs\DockerDesktop\resources\bin` ao `PATH` apenas do processo, ajustando o caminho à instalação local.

```text
docker build --platform linux/amd64 --no-cache -f deploy/spikes/Dockerfile -t cafi-spikes:s1 .
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges cafi-spikes:s1
```

O primeiro comando reconstrói sem cache de camadas de build. Imagem base e fonte criptográfica são verificadas por digest/SHA-256; a toolchain e os pacotes do SO estão fixados transitivamente pelo digest da imagem, sem `apt upgrade` ou instalação flutuante. O prefixo `/opt/cafi-openssl` isola a biblioteca compilada do OpenSSL do host e da cópia originalmente fornecida pela imagem. O download é necessário apenas no build; o diagnóstico funciona sem rede, sem volumes, sem serviços e sem segredos.

Para registrar a revisão de entrada no inventário em PowerShell:

```powershell
$revision = git rev-parse HEAD
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges -e "CAFI_CODE_REVISION=$revision" cafi-spikes:s1
```

Em Linux use `-e CAFI_CODE_REVISION="$(git rev-parse HEAD)"`. Ao testar alterações ainda não commitadas, registre separadamente a task e os hashes dos arquivos em execução; `HEAD` sozinho é apenas a base. Saída não zero indica falha e nunca deve ser convertida em sucesso ou skip.

## Prova ECDSA S1-04

Com a imagem acima construída, execute na raiz do repositório em PowerShell:

```powershell
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --mount "type=bind,source=$((Get-Location).Path)\spikes\signatures\ecdsa,target=/proof,readonly" cafi-spikes:s1 python /proof/proof.py
```

Em shell Linux, substitua o argumento de montagem por `--mount "type=bind,source=$(pwd)/spikes/signatures/ecdsa,target=/proof,readonly"`. A opção `--corrupt-original` após o nome do script perturba o caso positivo e deve produzir saída não zero; não a use na execução normal. O comando monta apenas a prova, não altera a imagem nem seu diagnóstico padrão. A [evidência](../docs/sprint-1/evidence/ecdsa.json) identifica a revisão-base, o hash da prova e a biblioteca efetivamente carregada.

O processo gera duas chaves temporárias em memória usando EVP, assina bytes sintéticos fixos e verifica o original e três alterações. O formato da assinatura EVP ECDSA é ASN.1 DER, não `r || s`. Não há subprocesso por operação nem persistência das chaves. Isto não testa contratos, autorização de chaves, proteção contra host comprometido ou interoperabilidade; `ctypes` continua binding experimental de baixo nível e a stack não está aprovada.

## Prova ML-DSA-65 S1-05

Reutilize a imagem `cafi-spikes:s1` e execute na raiz do repositório em PowerShell:

```powershell
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --mount "type=bind,source=$((Get-Location).Path)\spikes\signatures\ml-dsa,target=/proof,readonly" cafi-spikes:s1 python /proof/proof.py
```

Em shell Linux, use `--mount "type=bind,source=$(pwd)/spikes/signatures/ml-dsa,target=/proof,readonly"`. Acrescente `--corrupt-original` após o script para forçar a rejeição do caso que deveria passar: a saída deve ser não zero. Dependência indisponível também é falha.

O binding `ctypes` usa `EVP_PKEY_sign_message_init` e `EVP_PKEY_verify_message_init` com contexto vazio explícito, `message-encoding=1` e `mu=0`. OpenSSL recebe a mensagem sintética inteira e aplica o modo puro, sem pré-hash no script. O original é aceito; alterações no payload e na assinatura, outra chave pública e contexto não vazio são rejeitados. As duas chaves são geradas em memória pelo OpenSSL; só os componentes públicos são codificados, sem criar arquivos.

A assinatura tem 3309 bytes brutos ou 4412 caracteres Base64 padrão sem quebras. A pública tem 1952 bytes brutos, 1974 bytes em SPKI DER ou 2726 bytes em SPKI PEM emitido pelo OpenSSL. A [evidência sanitizada](../docs/sprint-1/evidence/ml-dsa.json) registra medições, referências, hashes, versões e códigos de saída. Esta prova não valida TLS, contratos ou a stack de produção.

## Prova TLS 1.3 mTLS com X25519 S1-06

Reutilize a imagem `cafi-spikes:s1`. Na raiz do repositório, em PowerShell:

```powershell
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 65534:65534 --tmpfs /tmp:rw,noexec,nosuid,nodev,size=1m,mode=0700,uid=65534,gid=65534 --mount "type=bind,source=$((Get-Location).Path)\spikes\tls,target=/proof,readonly" cafi-spikes:s1 python /proof/proof.py
```

Em shell Linux, use `--mount "type=bind,source=$(pwd)/spikes/tls,target=/proof,readonly"`. Para verificar que uma falha do caso positivo resulta em saída não zero, acrescente `--wrong-positive-name` após o script. Dependência ausente ou grupo não observável também resulta em falha.

O contêiner roda sem root, sem rede externa e sem portas publicadas. O listener abre apenas `127.0.0.1` em porta efêmera; cada caso usa sockets e objetos `SSL` novos. O tmpfs de 1 MiB, com acesso exclusivo ao UID do processo, guarda apenas a PKI efêmera: diretório `0700`, privadas `0600`, remoção automática e nenhuma escrita no repositório. As chaves de TLS são independentes das chaves de assinatura de mensagens. A CLI OpenSSL apenas emite certificados; cliente e servidor executam `SSL_connect` e `SSL_accept` em CPython via `ctypes`, com prazo de I/O de cinco segundos por conexão.

Ambos limitam versão, grupo, suíte e assinatura de autenticação a TLS 1.3, X25519, `TLS_AES_256_GCM_SHA384` e `ecdsa_secp256r1_sha256`. A prova exige cadeia até a CA de laboratório e SAN DNS exato de ambos os pares, sem CN ou wildcard. O teste repete a conexão com os mesmos contextos TLS e verifica ausência de cache, tickets, retomada e 0-RTT. O servidor só envia a confirmação cifrada após verificar o cliente. `SSL_get0_group_name` lê o grupo efetivo em ambas as pontas; a [evidência sanitizada](../docs/sprint-1/evidence/tls-x25519.json) conserva a grafia `x25519` devolvida pela biblioteca e os retornos dos casos negativos. Esta é uma prova local; não testa grupo híbrido, autorização de aplicação nem interoperabilidade com outra implementação.

## Prova TLS 1.3 mTLS com X25519MLKEM768 S1-07

Use a mesma imagem e as mesmas restrições de S1-06. Execute o comando duas vezes, em invocações separadas, para recriar o processo, a PKI, os contextos e as conexões:

```powershell
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 65534:65534 --tmpfs /tmp:rw,noexec,nosuid,nodev,size=1m,mode=0700,uid=65534,gid=65534 --mount "type=bind,source=$((Get-Location).Path)\spikes\tls,target=/proof,readonly" cafi-spikes:s1 python /proof/proof.py --hybrid
```

O modo `--hybrid` preserva a suíte, a autenticação ECDSA tradicional, os cinco negativos de mTLS/SAN e os controles contra retomada e 0-RTT. Em cada processo, as duas conexões positivas exigem que `SSL_get0_group_name` retorne `X25519MLKEM768` nos dois lados. Com as mesmas identidades válidas, o cliente limitado a X25519 recebe um alerta fatal na negociação com o servidor limitado ao grupo híbrido (`no suitable key share` no servidor), sem fallback nem ACK.

Sem `--hybrid`, o cenário padrão continua restrito a X25519. Acrescente `--wrong-positive-name` ao comando híbrido para perturbar o primeiro caso positivo: a prova deve terminar com código não zero. A [evidência S1-07](../docs/sprint-1/evidence/tls-hybrid.json) registra as duas execuções híbridas e a regressão X25519 com os hashes do harness atualizado, sem substituir a evidência histórica S1-06.

## O que o diagnóstico comprova

`spikes/environment.py` carrega `libcrypto.so.3` e `libssl.so.3` por caminho absoluto, confere Python/OpenSSL carregados, consulta implementações ECDSA/ML-DSA-65 por `EVP_SIGNATURE_fetch` e resolve símbolos públicos necessários. Registra versão, hashes de bibliotecas, compilador, plataforma, configuração e revisão informada. Não gera chave, não assina, não verifica assinatura e não estabelece TLS. `proofsExecuted` permanece vazio.

As APIs EVP de mensagem completa são candidatas para ML-DSA puro com contexto vazio. `SSL_ctrl` e as APIs públicas de grupos são candidatas para controle/observação de TLS; macros de headers precisam ser vinculadas corretamente nas provas. A presença de símbolos não demonstra semântica, grupo negociado ou interoperabilidade. ECDSA/ML-DSA e cada handshake têm gates próprios nas próximas tasks; ausência de observação do grupo bloqueia aprovação.

O [manifesto fixado](../deploy/spikes/versions.json) registra versões, hashes e fontes oficiais; a conferência de 2026-11-24 está na evidência atual, incluindo o checksum oficial do release. Fontes: [release Python](https://www.python.org/downloads/release/python-31311/), [imagem oficial](https://hub.docker.com/_/python), [ctypes](https://docs.python.org/3.13/library/ctypes.html), [OpenSSL](https://openssl-library.org/source/), [ML-DSA](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ML-DSA/) e [grupos TLS](https://docs.openssl.org/3.5/man3/SSL_CTX_set1_curves/). Python 3.13.11 não é a versão mais recente: foi fixada como candidato de laboratório disponível por digest, sem declaração de adequação de segurança para produção. A seleção será revista na ADR conforme as provas.

## Arquivos locais e segredos

Privadas das futuras provas devem ser temporárias e geradas dentro do contêiner, ou montadas de diretório externo ao repositório com acesso restrito. Nunca reutilizar chave TLS para assinatura de mensagem. `.gitignore` e `.dockerignore` excluem nomes convencionais de segredos, arquivos temporários e caches; isso não substitui inspeção do conteúdo antes de commit. Chaves públicas e relatórios sanitizados podem ser versionados explicitamente. Não use `git add .` para incluir resultados automaticamente.

Este ambiente não contém serviços financeiros, banco, conectores, migração ou benchmark. Nenhuma prova criptográfica é liberada por este inventário.
