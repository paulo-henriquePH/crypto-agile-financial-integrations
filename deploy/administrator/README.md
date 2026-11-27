# Administrador SOAP 1.2 — S2-11

Processo `services.administrator.serve`, sem worker da plataforma. O listener recebe
`POST /soap` na rede interna do cenário, como `administrator.cafi.test:8443`. A terminação
direta C1 usa o cliente/servidor h11 da [ADR 0001](../../docs/adr/0001-stack.md); não há
proxy, porta publicada nem WSDL gerado pelo serviço. Use o [WSDL congelado](../../contracts/soap/administrator.wsdl)
com o endereço de laboratório no lugar do placeholder. O `Content-Type` de cada
POST é `application/soap+xml; action="urn:cafi:administrator:v1:RegisterOperation"`
ou `application/soap+xml; action="urn:cafi:administrator:v1:GetOperation"`.

- `RegisterOperation` devolve `200` com o snapshot terminal persistido (inclusive
  em reenvio válido). Não liquida nem altera a boleta. `GetOperation` lê o registro
  independente; consulta nova não reaproveita a ausência de uma consulta anterior.
- Faults de aplicação usam `400`/`s:Sender` e indisponibilidade do banco usa
  `500`/`s:Receiver`. A decisão vem do **envelope assinado** em
  `Fault/Detail/Message`, não do status, `Code` ou `Reason` externos. Ausência
  autenticada é `NOT_FOUND` não retentável; `IDEMPOTENCY_CONFLICT` distingue
  `MESSAGE_ID_REUSED` de `BUSINESS_DIGEST_MISMATCH` pelo `Message` assinado.
  `FORBIDDEN` indica falta de autorização atual. Uma primeira boleta
  não processável recebe `INVALID_BUSINESS` sem snapshot. Rejeições antes de
  estabelecer contexto de mensagem confiável podem encerrar o enlace ou
  retornar HTTP vazio, sem resultado de negócio.
- A [migração](../persistence/migrations/administrator/002_snapshots.sql) é aplicada
  somente ao banco `administrator`; o processo monta seu login PostgreSQL, sua
  identidade mTLS e sua chave de mensagem. O cliente de laboratório monta só
  a identidade do participante `PLATFORM` desse enlace, sem credencial SQL.
  As privadas e senhas ficam em volumes Docker exclusivos do cenário. Inbox,
  snapshot e recibo da primeira tentativa válida têm o mesmo commit.
- `Sequence` continua inteiro positivo no contrato. Seus dígitos canônicos ficam
  em texto no armazenamento interno; o limite de 256 KiB continua valendo para
  cada envelope. Antes de gravar, o simulador mede as duas respostas de sucesso
  com os metadados completos e 96 caracteres de Base64 reservados para a
  assinatura C1. Se uma não couber, devolve `INVALID_BUSINESS` /
  `SNAPSHOT_RESPONSE_TOO_LARGE` no Fault assinado e grava só o recibo, sem inbox
  nem snapshot. O teste é sobre os bytes serializados, não a quantidade de dígitos.

## Reprodução

Na raiz, com Docker Linux `amd64`, Compose, Python 3.10+ no host e a
[imagem `cafi-transport:s2-03`](../../spikes/s2-03/README.md):

```powershell
# Só se Docker Desktop não estiver no PATH do processo:
$env:PATH = "$env:LOCALAPPDATA\Programs\DockerDesktop\resources\bin;$env:PATH"
py -B deploy/administrator/lab.py
```

No Linux, use `python3 -B` no lugar de `py -B`. O verificador constrói as imagens,
aplica migrações e cadastros num projeto Compose novo, provisiona chaves efêmeras
e inicia o listener e o cliente em processos diferentes. Executa os [casos SOAP](../../tests/administrator/exchanges.py)
com assinaturas novas e mTLS real e, por fora, verifica as tabelas e os logins
no PostgreSQL. A regressão da sequência registra e consulta 4.300, 4.301 e
150.001 dígitos, confere o texto persistido e testa léxicos inválidos, adulteração
e a distinção entre conflito de negócio e de bytes. A fase de tamanho envia
requisições válidas de exatamente 262.144 bytes, compara as duas formas de
resposta, testa o limite de saída e um byte acima, e confere replay, consulta,
Faults e recibos. O runner reinicia o serviço e revoga temporariamente a permissão
de escrita dos recibos para provocar rollback real e remove a concessão de
carteira para verificar a autorização a cada tentativa. Essas ações são do
operador do cenário, não da interface SOAP. O `finally` remove só os recursos
desse projeto e de suas ferramentas. Rode as provas Docker em série.

Para repetir as regressões, com a [imagem `cafi-soap:s1`](../../contracts/soap/README.md#reprodução)
já construída, execute também na raiz:

```powershell
$iso = @('--rm','--platform','linux/amd64','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--mount',"type=bind,source=$((Get-Location).Path),target=/work,readonly",'-w','/work','-e','PYTHONDONTWRITEBYTECODE=1')
powershell -NoProfile -File scripts/verify-c1/verify.ps1
docker run @iso cafi-soap:s1 python -m unittest discover -s tests/contracts -p test_administrator_soap.py -v
docker run @iso cafi-soap:s1 python tests/contracts/verify_signed_vectors.py
py -B deploy/persistence/lab.py verify
powershell -NoProfile -File spikes/s2-03/verify.ps1 -BodyProof
powershell -NoProfile -File spikes/s2-03/verify.ps1
```

A [evidência sanitizada](../../docs/sprint-2/evidence/s2-11.json) distingue
essa integração da prova isolada dos vetores/stack. Não há envio SOAP
automático pela plataforma, conciliação, teste de migração de perfil nem aceite
do fluxo C1 ponta a ponta neste recorte.
