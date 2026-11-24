# Vetores Exclusive XML C14N — S1-13

O [XSD comum](../../schemas/xml/signed-content.xsd) define os elementos globais `SignedContent` e `Signatures` de `urn:cafi:v1`, para reuso pelo contrato SOAP. O [executor](../../../tests/contracts/canonical_xml.py) usa o caminho fixo da prova `/s:Envelope/s:Body/c:Message/c:SignedContent`, com `s = http://www.w3.org/2003/05/soap-envelope` e `c = urn:cafi:v1`. Esses nomes indicam **URIs**, não prefixos obrigatórios. A prova exige um único Body e uma única mensagem, sem Header, com `SignedContent` seguido de `Signatures` como irmãos. Não é um WSDL nem define as ações, wrappers ou Faults finais de S1-16. O futuro adaptador deve fixar o caminho por tipo de mensagem, inclusive em `Detail` no Fault, e não deixar metadados externos redefinirem ação ou destino.

## Mapeamento do conteúdo protegido

- `SignedContent` contém exatamente `Protected` e `Payload`, nessa ordem. `Protected` representa os campos homônimos de [S1-11](../../messages/README.md) com inicial maiúscula e ordem do XSD. `Signers/Signer` é a lista ordenada protegida, com atributos não qualificados `algorithm` e `keyId`. `Signatures/Signature` repete o par e carrega o valor Base64. O executor confere ordem, quantidade e correspondência conforme o perfil; as assinaturas são **ilustrativas**.
- A representação XML cobre as mensagens da interface SOAP: `QUERY_ADMIN_RECORD` tem `Payload` vazio; `REGISTER_OPERATION` e os dois resultados de negócio usam snapshot terminal com `ManagerId`, `Boleta`, `State`, `Sequence` e, conforme o estado, `Reason` e `RejectionOrigin`. O erro contém `Code`, `Message`, `CorrelationId`, `Retryable`, `Details`; `Details/Detail` repete itens ordenados de atributos `field` e `issue`. Esses são os mesmos campos lógicos do [envelope JSON](../../messages/envelope.schema.json), sem manter uma segunda cópia não assinada. Decimais e quantidade da [boleta](../../schemas/boleta.schema.json) preservam sua forma textual, incluindo zeros finais; não se aplicam conversão numérica nem `strip` aos dados.
- Todas as mensagens SOAP correspondem a uma operação já identificada, inclusive seus erros: `OperationId` é obrigatório neste XSD, não um UUID sintético para criação REST. `RequestMessageId` é proibido em requisições e obrigatório em resultados e erros. O executor confere formato/calendário UTC, tipo de payload, restrições do estado terminal e igualdade dos IDs de correlação no erro. Não valida a requisição original, janela em relação ao relógio, autorização, política local ou regras financeiras; essas verificações continuam obrigatórias onde aplicáveis. Não aceita ausências substituídas por `xsi:nil`, valores `xsi:type` ou campos desconhecidos.

## Parser e região canonicalizada

O executor limita a entrada completa a 256 KiB antes de analisar e exige XML 1.0 UTF-8. A pré-validação por eventos do Expat interrompe no início de qualquer DOCTYPE, desativa leitura de entidades de parâmetro e impede referências externas, profundidade acima de 32 (raiz no nível 1), XInclude e instruções de processamento. Atributos `xsi:*` (inclusive hints de schema) e `xml:*` são recusados para evitar interpretação dependente de contexto. A árvore usada na prova é construída uma única vez pelo lxml com DTD, entidades, acesso à rede, recuperação e resolução local/remota desativados; não se invoca XInclude. O único XSD carregado é local e fixo, sem imports ou atributos introduzidos pelo validador.

O próprio elemento selecionado pelo caminho fixo é validado e passado à libxml2 para Exclusive C14N 1.0 **sem comentários e sem lista de prefixos inclusivos**. Não há busca por ID/XPath externo, reparse, reserialização intermediária ou limpeza de whitespace. `check_expected` só entrega esse mesmo objeto após a comparação com bytes e digest congelados. O teste consome valores diretamente nele e concatena todos os trechos de texto do campo, inclusive os separados por comentário: usar só `.text` poderia mudar o valor lido com os mesmos bytes canônicos. Isto demonstra o vínculo na prova; não é verificação de assinatura. S1-17 deverá verificar criptograficamente antes de consumir, sem reextrair ou alterar o nó entre as etapas.

## Bytes estáticos e referência independente

O [manifesto](manifest.json) aponta para entradas XML e arquivos `.canonical.b64`, que armazenam, em Base64, os bytes UTF-8 canônicos exatos (decodificados sem BOM nem quebra final). O SHA-256 é só conferência do vetor. `query` e `query-recontextualized` têm bytes iguais embora os ancestrais, prefixos SOAP, atributos ordenados na entrada, comentários e assinatura ilustrativa sejam diferentes. `error` mostra declaração de namespace usada só no descendente, ordenação/escape de atributos, Unicode, CDATA, CR e whitespace significativo. `registration` preserva escalas financeiras. Os negativos estáticos e as mutações da suíte verificam caminho único, troca/duplicação do nó, campos ordinais, rejeição de resolução e limites.

As expectativas foram congeladas a partir de [`XmlDsigExcC14NTransform`](https://learn.microsoft.com/dotnet/api/system.security.cryptography.xml.xmldsigexcc14ntransform), do .NET Framework 4.8.1 (`System.Security`, versão de arquivo observada em evidência), **não da função Python nem de outro wrapper libxml2**. O [conferidor](reference/check.ps1) usa o DOM .NET com DTD proibido, toma os quatro positivos pelo caminho fixo, fornece namespaces em escopo ao DOM de referência e pede ao .NET a transformação exclusiva sem comentários. Ele não é um segundo parser de entrada do executor. A regra de exclusividade segue a recomendação [W3C, §§2–3](https://www.w3.org/TR/xml-exc-c14n/#sec-Specification), e a serialização de atributos, caracteres e whitespace segue [Canonical XML 1.0, §2](https://www.w3.org/TR/2001/REC-xml-c14n-20010315#ProcessingModel). A execução de referência confere os arquivos sem sobrescrevê-los.

## Reprodução

Na raiz, com `cafi-spikes:s1` disponível e Docker no PATH do processo (PowerShell):

```powershell
docker build --platform linux/amd64 --target xml -f deploy/contracts/Dockerfile -t cafi-xml:s1 .
docker build -f deploy/contracts/Dockerfile -t cafi-jcs:s1 . # imagem sem lxml para a contraprova
$iso = @('--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--mount',"type=bind,source=$((Get-Location).Path),target=/work,readonly",'-w','/work','-e','PYTHONDONTWRITEBYTECODE=1')
docker run @iso cafi-xml:s1 python tests/contracts/canonical_xml.py
docker run @iso cafi-xml:s1 python -m unittest discover -s tests/contracts -p test_canonical_xml.py -v
docker run @iso cafi-xml:s1 python -m unittest discover -s tests/contracts -v
docker run @iso cafi-xml:s1 python tests/contracts/canonical_xml.py --invalid # saída 1
docker run @iso cafi-jcs:s1 python -m unittest discover -s tests/contracts -p test_canonical_xml.py -v # saída 1 (lxml ausente)
& .\contracts\vectors\xml\reference\check.ps1 # conferir referência em Windows PowerShell 5.1 / .NET Framework
```

O [lock do XML](../../../deploy/contracts/requirements-xml.txt) seleciona o wheel CPython 3.13, Linux amd64 manylinux 2.28, sem extras ou dependências Python transitivas. O Dockerfile instala por versão e hash; o alvo sem `--target` mantém a imagem JCS sem XML. [Evidência](../../../docs/sprint-1/evidence/xml-c14n.json): identificação da imagem, bibliotecas carregadas, resultados e hashes. Limites do transporte/concorrência e a validação integrada de SOAP e assinaturas estão fora desta prova.
