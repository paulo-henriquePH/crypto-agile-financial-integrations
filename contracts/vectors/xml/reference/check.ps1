# .NET Framework reference. Only parses the known positive inputs at this fixed path.
param([switch]$PrintExpected)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$type = [System.Security.Cryptography.Xml.XmlDsigExcC14NTransform]
"Reference: $($type.Assembly.FullName); $((Get-Item $type.Assembly.Location).VersionInfo.FileVersion)"
$vectors = Split-Path -Parent $PSScriptRoot
$manifest = Get-Content -Raw -Encoding UTF8 (Join-Path $vectors manifest.json) | ConvertFrom-Json
$cases = @($manifest.cases | Where-Object { $_.expected })
if ($cases.Count -eq 0) { throw 'No positive reference cases' }
foreach ($case in $cases) {
    $set = [System.Xml.XmlReaderSettings]::new()
    $set.DtdProcessing = 'Prohibit'
    $set.XmlResolver = $null
    $set.MaxCharactersInDocument = 262144
    $doc = [System.Xml.XmlDocument]::new()
    $doc.PreserveWhitespace = $true
    $doc.XmlResolver = $null
    $reader = [System.Xml.XmlReader]::Create((Join-Path $vectors $case.input), $set)
    try { $doc.Load($reader) } finally { $reader.Dispose() }
    $ns = [System.Xml.XmlNamespaceManager]::new($doc.NameTable)
    $ns.AddNamespace('s', 'http://www.w3.org/2003/05/soap-envelope')
    $ns.AddNamespace('c', 'urn:cafi:v1')
    $nodes = $doc.SelectNodes('/s:Envelope/s:Body/c:Message/c:SignedContent', $ns)
    if ($nodes.Count -ne 1) { throw "$($case.name): wrong reference path" }
    $node = $nodes.Item(0)

    # Supply the same in-scope namespaces to the independent DOM transform.
    # No C14N rules are implemented here; .NET decides what is visible/rendered.
    $sub = [System.Xml.XmlDocument]::new()
    $sub.PreserveWhitespace = $true
    $sub.XmlResolver = $null
    $copy = $sub.ImportNode($node, $true)
    foreach ($decl in $node.SelectNodes('namespace::*')) {
        if ($decl.Name -ne 'xmlns:xml' -and -not $copy.HasAttribute($decl.Name)) {
            [void]$copy.SetAttributeNode($sub.ImportNode($decl, $true))
        }
    }
    [void]$sub.AppendChild($copy)
    $transform = [System.Security.Cryptography.Xml.XmlDsigExcC14NTransform]::new($false)
    $transform.LoadInput($sub)
    $stream = $transform.GetOutput([System.IO.Stream])
    $content = [System.IO.MemoryStream]::new()
    $hash = [System.Security.Cryptography.SHA256]::Create()
    try {
        $stream.CopyTo($content)
        $bytes = $content.ToArray()
        $base64 = [Convert]::ToBase64String($bytes)
        $sha256 = [BitConverter]::ToString($hash.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant()
    } finally {
        $stream.Dispose()
        $content.Dispose()
        $hash.Dispose()
    }
    if ($PrintExpected) {
        "$($case.name) $($bytes.Length) $sha256 $base64"
    } else {
        $expected = (Get-Content -Encoding ASCII -Raw (Join-Path $vectors $case.expected)).Trim()
        if ($expected -cne $base64 -or $case.sha256 -cne $sha256) {
            throw "$($case.name): reference bytes or SHA-256 differ"
        }
        "$($case.name): $($bytes.Length) bytes; SHA-256 $sha256"
    }
}
