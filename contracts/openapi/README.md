# Contrato REST da plataforma

`platform.yaml` é uma especificação OpenAPI 3.1, **não um endpoint implementado**.
Os únicos caminhos são `POST /v1/operations` e
`POST /v1/operations/{operationId}/status-queries`. O `Location` identifica a
operação, mas não declara GET. A criação persistida, inclusive a rejeição LOCAL,
retorna 201; replay de mesmo negócio retorna 200 com novo envelope correlacionado.
O `operationId` protegido identifica o resultado e é diferente de `clientOrderId`.

Os exemplos apontam para arquivos locais e JSON Pointers. Todas as assinaturas
decodificam para `NOT_A_SIGNATURE`: **não são criptográficas**; S1-17 produzirá
vetores assinados. O exemplo de rejeição é um cenário alternativo, não uma
sequência junto da criação aceita: usa mesma identidade ilustrativa com valor
financeiro inválido. O checker correlaciona a entrada específica desse cenário,
não a requisição histórica incorporada ao corpus anterior.

OpenAPI 3.1 permite reutilizar JSON Schema draft 2020-12, `const` e `mutualTLS`
sem adaptar os schemas aprovados. `openapi-spec-validator` 0.7.1 valida o
documento; `jsonschema` 4.23.0 valida instâncias e formatos com registry local
fixo; regras semânticas e replay local são adicionais. URNs aprovados são
mapeados localmente, não obtidos da rede. Referências e exemplos fora da lista
de arquivos permitidos falham. O controle não verifica assinaturas, autenticação
real, estado persistido, frescor operacional ou comportamento de um servidor.
No erro 400 o teste usa uma mutação sintaticamente inválida em memória; falha de
parsing ou handshake pode impedir a produção de envelope assinado.

## Reprodução

Na raiz do repositório, PowerShell com a imagem base `cafi-spikes:s1` já
disponível (build usa PyPI; runtime não usa rede):

```powershell
$env:PATH = "C:\Users\Inteli\AppData\Local\Programs\DockerDesktop\resources\bin;$env:PATH"
docker build --platform linux/amd64 --target openapi -f deploy/contracts/Dockerfile -t cafi-openapi:s1 .
$opts = @('run','--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--mount',"type=bind,source=$((Get-Location).Path),target=/work,readonly",'-w','/work','-e','PYTHONDONTWRITEBYTECODE=1')
docker @opts cafi-openapi:s1 python tests/contracts/check_platform_openapi.py
docker @opts cafi-openapi:s1 python -m unittest discover -s tests/contracts -v
docker @opts cafi-openapi:s1 python tests/contracts/check_boleta_schema.py
docker @opts cafi-openapi:s1 python tests/contracts/check_events_schema.py
docker @opts cafi-openapi:s1 python tests/contracts/check_messages_schema.py
docker @opts cafi-openapi:s1 python tests/contracts/check_platform_openapi.py --invalid # saída 1
docker @opts cafi-xml:s1 python tests/contracts/check_platform_openapi.py # dependência ausente, saída 1
```

Os hashes dos wheels estão em `deploy/contracts/requirements-openapi.txt` e
`requirements-boleta.txt`; suas fontes são os metadados PyPI
`https://pypi.org/pypi/<nome>/<versão>/json`. O alvo herda ainda JCS/XML e seus
arquivos de requisitos fixados. A evidência de execução está em
`docs/sprint-1/evidence/platform-openapi.json`. O histórico remoto de custodiante
permanece explicitamente fora de S1-14.
