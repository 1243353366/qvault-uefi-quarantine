# Execute one function out of a larger script, without running the script's body.
# Used to test shipped logic (tree ordering, name matching) where it actually lives.
param([string]$ScriptPath, [string]$FunctionName, [string]$ParamsJson)

$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$tokens, [ref]$errors)
if ($errors) { Write-Output ('{"error":"parse","detail":"' + ($errors[0].Message -replace '"','') + '"}'); exit 1 }

$fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
      Where-Object { $_.Name -eq $FunctionName } | Select-Object -First 1
if (-not $fn) { Write-Output '{"error":"missing"}'; exit 1 }
. ([scriptblock]::Create($fn.Extent.Text))

$spec = $ParamsJson | ConvertFrom-Json
$ht = @{}
foreach ($prop in $spec.PSObject.Properties) {
    if ($prop.Name -eq 'Edges') {
        $edges = @{}
        foreach ($e in $prop.Value.PSObject.Properties) { $edges[[int]$e.Name] = @($e.Value) }
        $ht['Edges'] = $edges
    } else {
        $ht[$prop.Name] = $prop.Value
    }
}
$out = & $FunctionName @ht
if ($null -eq $out) { Write-Output 'null' } else { $out | ConvertTo-Json -Compress }
