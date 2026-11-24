# Administrador SOAP 1.2

Contrato preliminar SOAP 1.2 document/literal: `RegisterOperation` usa ação
`urn:cafi:administrator:v1:RegisterOperation`, `GetOperation` usa
`urn:cafi:administrator:v1:GetOperation`. O endereço `.invalid` é ilustrativo.
O corpo contém `urn:cafi:v1:Message`, com `SignedContent` e `Signatures`,
reutilizando o XSD comum sem modificá-lo. Fault usa `Detail/Message`.
O transporte deverá exigir mTLS; autenticação de transporte não substitui
verificação da assinatura da mensagem. As assinaturas dos exemplos são
ilustrativas, não verificáveis criptograficamente.

## Mapeamento

`protected`, `payload` e `signatures` correspondem a `SignedContent/Protected`,
`SignedContent/Payload` e `Signatures`; nomes de propriedades viram elementos
com a primeira letra maiúscula, na ordem do XSD comum. `signers` é
`Signers/Signer` e suas propriedades `algorithm` e `keyId` são atributos; o
mesmo ocorre em `Signature`, cujo texto é `value`. `details` é
`Details/Detail`, cujos atributos `field` e `issue` preservam a ordem.
`instructionVersion`, `policyVersion` e `sequence` são inteiros JSON e
texto decimal XML sem zeros iniciais; `retryable` representa booleano JSON por
`true`/`false`. `quantity`, taxas, PU e valor financeiro são **strings** nos
dois formatos, preservando exatamente escala e zeros; não converter via
float. `canonicalization` é específico da representação: JCS no JSON e
EXCLUSIVE_C14N_1_0 no XML, portanto os bytes e as assinaturas não são
intercambiáveis. A representação preserva os valores de negócio, não a
assinatura nem os bytes da outra serialização.

`QUERY_ADMIN_RECORD` não contém payload; ambos resultados contêm snapshot
terminal. Ausência autenticada usa Fault `ERROR` com `NOT_FOUND`, `retryable`
false e correlação no conteúdo assinado. O `Reason` e `Code` externos são
metadados de transporte, não substituem o erro assinado nem autorizam atualização.
Respostas correlacionam identificador da requisição, operação, versão,
ambiente e as identidades invertidas; o chamador deve ainda conferir ação,
política, validade temporal, autorização e assinatura antes de consumir.

O checker limita profundidade/tamanho, rejeita DTD, entidades, XInclude,
instruções de processamento e hints; `xml:lang` é permitido exclusivamente em
`Fault/Reason/Text`, como requer SOAP 1.2. O mesmo nó `SignedContent` validado
é canonicalizado e devolvido, sem reparse. As regras financeiras completas e
verificação criptográfica não são executadas. O endereço é placeholder, não há
serviço; carregar o WSDL não comprova interoperabilidade. A camada de
aplicação deve conferir ação HTTP, destino mTLS, correlação e assinatura.

## Reprodução

Com Docker no PATH e `cafi-spikes:s1` local:

```powershell
docker build --platform linux/amd64 --target soap -f deploy/contracts/Dockerfile -t cafi-soap:s1 .
$iso = @('--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--mount',"type=bind,source=$((Get-Location).Path),target=/work,readonly",'-w','/work','-e','PYTHONDONTWRITEBYTECODE=1')
docker run @iso cafi-soap:s1 python tests/contracts/check_administrator_soap.py
docker run @iso cafi-soap:s1 python -m unittest discover -s tests/contracts -v
docker run @iso cafi-soap:s1 python tests/contracts/check_administrator_soap.py --invalid-wsdl # saída 1
```

O XSD de envelope é perfil estrito local, não implementação genérica de SOAP.
O WSDL é também validado pelo libxml2 contra os schemas originais
[WSDL 1.1](https://schemas.xmlsoap.org/wsdl/2003-02-11.xsd) e
[extensão SOAP 1.2](https://schemas.xmlsoap.org/wsdl/soap12/wsdl11soap12.xsd),
distribuídos sem alterações em `reference/`, incluindo seus avisos e licenças.
A origem da extensão é a [submissão de membros W3C de 2006](https://www.w3.org/submissions/2006/SUBM-wsdl11soap12-20060405/),
não uma recomendação W3C. Seus SHA-256 são, respectivamente,
`5ba4c0d0c2804572f1afca3ecda2e9c66b98601d781519e404136fdf766573e6` e
`01ec1f55fd3aca2d1ed7a29f95fe6fbae659ce45fe71085259203b143b0fddac`.
`reference/validation.xsd` apenas importa ambos os schemas por caminhos locais.
O checker fixa os hashes e complementa a extensibilidade lax do WSDL com
verificação de binding SOAP 1.2, transporte, document/literal, operações,
ações e Fault. Essa combinação não é validação semântica genérica de WSDL.
Imports e includes são limitados aos arquivos locais conhecidos; Zeep é
configurado com transporte que não envia requisições. Faltas de biblioteca
produzem saída não zero. A validação da assinatura real pertence a S1-17.
