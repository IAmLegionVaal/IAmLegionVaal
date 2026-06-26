#requires -Version 7.2

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9-]+$')]
    [string]$Owner,

    [Parameter(Mandatory)]
    [ValidateRange(1, 100)]
    [int]$Page,

    [ValidateRange(1, 100)]
    [int]$PerPage = 100,

    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = (Join-Path $PWD "audit-page-$Page")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$token = $env:GITHUB_TOKEN
if ([string]::IsNullOrWhiteSpace($token)) {
    throw 'GITHUB_TOKEN is required.'
}

$headers = @{
    Accept = 'application/vnd.github+json'
    Authorization = "Bearer $token"
    'User-Agent' = 'IAmLegionVaal-Portfolio-Audit'
    'X-GitHub-Api-Version' = '2022-11-28'
}

$workRoot = Join-Path ([IO.Path]::GetTempPath()) "portfolio-audit-$Page-$([guid]::NewGuid().ToString('N'))"
$findings = [System.Collections.Generic.List[object]]::new()
$repositoryResults = [System.Collections.Generic.List[object]]::new()

function Add-Finding {
    param(
        [Parameter(Mandatory)][string]$Repository,
        [Parameter(Mandatory)][ValidateSet('Error', 'Warning', 'Info')][string]$Severity,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Message,
        [string]$Path = '',
        [int]$Line = 0
    )

    $findings.Add([pscustomobject]@{
        Repository = $Repository
        Severity = $Severity
        Category = $Category
        Path = $Path
        Line = $Line
        Message = $Message
    })
}

function Test-IgnoredPath {
    param([Parameter(Mandatory)][string]$Path)

    return $Path -match '[/\\](node_modules|vendor|\.venv|venv|dist|build|bin|obj|packages|coverage)[/\\]'
}

function Invoke-ExternalCheck {
    param(
        [Parameter(Mandatory)][string]$Repository,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string]$Command,
        [Parameter(Mandatory)][string[]]$Arguments
    )

    $output = @(& $Command @Arguments 2>&1)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        Add-Finding -Repository $Repository -Severity Error -Category $Category `
            -Path $FilePath -Message (($output | Out-String).Trim())
    }
}

try {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    New-Item -Path $workRoot -ItemType Directory -Force | Out-Null

    $listUri = "https://api.github.com/users/$Owner/repos?type=owner&sort=full_name&direction=asc&per_page=$PerPage&page=$Page"
    $repositories = @(Invoke-RestMethod -Uri $listUri -Headers $headers -Method Get)

    foreach ($repository in $repositories) {
        $repoName = [string]$repository.name
        $fullName = [string]$repository.full_name
        $defaultBranch = [string]$repository.default_branch
        $repoWork = Join-Path $workRoot ($repoName -replace '[^A-Za-z0-9._-]', '_')
        $zipPath = "$repoWork.zip"
        $repoStarted = Get-Date
        $scanStatus = 'Completed'

        try {
            if ([string]::IsNullOrWhiteSpace($defaultBranch)) {
                Add-Finding -Repository $fullName -Severity Warning -Category Repository `
                    -Message 'Repository has no default branch.'
                $scanStatus = 'SkippedNoDefaultBranch'
                continue
            }

            $archiveUri = "https://api.github.com/repos/$fullName/zipball/$([uri]::EscapeDataString($defaultBranch))"
            Invoke-WebRequest -Uri $archiveUri -Headers $headers -OutFile $zipPath -MaximumRedirection 10
            Expand-Archive -LiteralPath $zipPath -DestinationPath $repoWork -Force

            $repoRoot = Get-ChildItem -LiteralPath $repoWork -Directory | Select-Object -First 1
            if (-not $repoRoot) {
                throw 'Downloaded archive did not contain a repository directory.'
            }

            $allFiles = @(Get-ChildItem -LiteralPath $repoRoot.FullName -File -Recurse -Force |
                Where-Object { -not (Test-IgnoredPath -Path $_.FullName) })

            $powerShellFiles = @($allFiles | Where-Object Extension -ieq '.ps1')
            $pythonFiles = @($allFiles | Where-Object Extension -ieq '.py')
            $shellFiles = @($allFiles | Where-Object Extension -ieq '.sh')
            $jsonFiles = @($allFiles | Where-Object Extension -ieq '.json')
            $yamlFiles = @($allFiles | Where-Object { $_.Extension -in '.yml', '.yaml' })
            $workflowFiles = @($allFiles | Where-Object { $_.FullName -match '[/\\]\.github[/\\]workflows[/\\]' })

            foreach ($file in $powerShellFiles) {
                $tokens = $null
                $parseErrors = $null
                [void][System.Management.Automation.Language.Parser]::ParseFile(
                    $file.FullName,
                    [ref]$tokens,
                    [ref]$parseErrors
                )

                foreach ($parseError in @($parseErrors)) {
                    Add-Finding -Repository $fullName -Severity Error -Category PowerShellParser `
                        -Path $file.FullName.Substring($repoRoot.FullName.Length + 1) `
                        -Line $parseError.Extent.StartLineNumber -Message $parseError.Message
                }

                $content = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop
                $relativePath = $file.FullName.Substring($repoRoot.FullName.Length + 1)

                $mutationPattern = '(?im)\b(Remove-Item|Set-ItemProperty|New-LocalUser|Set-LocalUser|Add-LocalGroupMember|Restart-Service|Stop-Service|Start-Service|Set-Service|Remove-AppxPackage|Add-AppxPackage|Restart-Computer|Clear-DnsClientCache)\b'
                if ($content -match $mutationPattern -and $content -notmatch '(?is)CmdletBinding\s*\([^)]*SupportsShouldProcess') {
                    Add-Finding -Repository $fullName -Severity Warning -Category PowerShellSafety `
                        -Path $relativePath -Message 'Mutating commands are present without SupportsShouldProcess/WhatIf support.'
                }

                if ($content -match '(?im)\bInvoke-Expression\b|\biex\s*\(') {
                    Add-Finding -Repository $fullName -Severity Warning -Category PowerShellSafety `
                        -Path $relativePath -Message 'Dynamic expression execution detected; review for injection risk.'
                }

                $secretMatches = [regex]::Matches(
                    $content,
                    '(?im)^\s*\$?(password|passwd|pwd|api[_-]?key|token|client[_-]?secret)\s*=\s*["''][^"'']{8,}["'']\s*$'
                )
                foreach ($secretMatch in $secretMatches) {
                    $line = ($content.Substring(0, $secretMatch.Index) -split "`n").Count
                    Add-Finding -Repository $fullName -Severity Warning -Category SecretExposure `
                        -Path $relativePath -Line $line -Message 'Possible hard-coded credential or token assignment.'
                }
            }

            if ($powerShellFiles.Count -gt 0 -and $workflowFiles.Count -eq 0) {
                Add-Finding -Repository $fullName -Severity Warning -Category CI `
                    -Message 'PowerShell files are present but no GitHub Actions workflow was found.'
            }

            if ($powerShellFiles.Count -gt 0 -and (Get-Command Invoke-ScriptAnalyzer -ErrorAction SilentlyContinue)) {
                $analyzerFindings = @(Invoke-ScriptAnalyzer -Path $repoRoot.FullName -Recurse -Severity Error)
                foreach ($finding in $analyzerFindings) {
                    Add-Finding -Repository $fullName -Severity Error -Category PSScriptAnalyzer `
                        -Path ([string]$finding.ScriptPath).Substring($repoRoot.FullName.Length + 1) `
                        -Line $finding.Line -Message "$($finding.RuleName): $($finding.Message)"
                }
            }

            foreach ($file in $jsonFiles) {
                if ($file.Length -gt 10MB) {
                    Add-Finding -Repository $fullName -Severity Info -Category Json `
                        -Path $file.FullName.Substring($repoRoot.FullName.Length + 1) `
                        -Message 'JSON validation skipped because the file exceeds 10 MB.'
                    continue
                }

                try {
                    Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json -ErrorAction Stop | Out-Null
                }
                catch {
                    Add-Finding -Repository $fullName -Severity Error -Category Json `
                        -Path $file.FullName.Substring($repoRoot.FullName.Length + 1) -Message $_.Exception.Message
                }
            }

            foreach ($file in $yamlFiles) {
                Invoke-ExternalCheck -Repository $fullName -Category Yaml `
                    -FilePath $file.FullName.Substring($repoRoot.FullName.Length + 1) `
                    -Command 'python3' -Arguments @('-c', 'import sys,yaml; yaml.safe_load(open(sys.argv[1], encoding="utf-8"))', $file.FullName)
            }

            foreach ($file in $pythonFiles) {
                Invoke-ExternalCheck -Repository $fullName -Category PythonCompile `
                    -FilePath $file.FullName.Substring($repoRoot.FullName.Length + 1) `
                    -Command 'python3' -Arguments @('-m', 'py_compile', $file.FullName)
            }

            if ($shellFiles.Count -gt 0 -and (Get-Command shellcheck -ErrorAction SilentlyContinue)) {
                foreach ($file in $shellFiles) {
                    Invoke-ExternalCheck -Repository $fullName -Category ShellCheck `
                        -FilePath $file.FullName.Substring($repoRoot.FullName.Length + 1) `
                        -Command 'shellcheck' -Arguments @('-S', 'error', $file.FullName)
                }
            }

            $repositoryResults.Add([pscustomobject]@{
                Repository = $fullName
                Archived = [bool]$repository.archived
                Fork = [bool]$repository.fork
                DefaultBranch = $defaultBranch
                PowerShellFiles = $powerShellFiles.Count
                PythonFiles = $pythonFiles.Count
                ShellFiles = $shellFiles.Count
                JsonFiles = $jsonFiles.Count
                WorkflowFiles = $workflowFiles.Count
                Findings = @($findings | Where-Object Repository -eq $fullName).Count
                ScanStatus = $scanStatus
                DurationSeconds = [math]::Round(((Get-Date) - $repoStarted).TotalSeconds, 2)
            })
        }
        catch {
            $scanStatus = 'Failed'
            Add-Finding -Repository $fullName -Severity Error -Category Scanner `
                -Message $_.Exception.Message

            $repositoryResults.Add([pscustomobject]@{
                Repository = $fullName
                Archived = [bool]$repository.archived
                Fork = [bool]$repository.fork
                DefaultBranch = $defaultBranch
                PowerShellFiles = 0
                PythonFiles = 0
                ShellFiles = 0
                JsonFiles = 0
                WorkflowFiles = 0
                Findings = @($findings | Where-Object Repository -eq $fullName).Count
                ScanStatus = $scanStatus
                DurationSeconds = [math]::Round(((Get-Date) - $repoStarted).TotalSeconds, 2)
            })
        }
        finally {
            Remove-Item -LiteralPath $repoWork, $zipPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    $repositoryResults | Export-Csv -LiteralPath (Join-Path $OutputPath 'repositories.csv') -NoTypeInformation -Encoding UTF8
    $findings | Export-Csv -LiteralPath (Join-Path $OutputPath 'findings.csv') -NoTypeInformation -Encoding UTF8

    [ordered]@{
        Owner = $Owner
        Page = $Page
        PerPage = $PerPage
        GeneratedAtUtc = [DateTime]::UtcNow
        RepositoryCount = $repositoryResults.Count
        ErrorCount = @($findings | Where-Object Severity -eq Error).Count
        WarningCount = @($findings | Where-Object Severity -eq Warning).Count
        InfoCount = @($findings | Where-Object Severity -eq Info).Count
        Repositories = $repositoryResults
        Findings = $findings
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $OutputPath 'report.json') -Encoding UTF8

    $summary = @(
        "# Portfolio audit — page $Page"
        ''
        "- Repositories scanned: $($repositoryResults.Count)"
        "- Errors: $(@($findings | Where-Object Severity -eq Error).Count)"
        "- Warnings: $(@($findings | Where-Object Severity -eq Warning).Count)"
        "- Informational: $(@($findings | Where-Object Severity -eq Info).Count)"
        ''
        '## Error findings'
        ''
    )

    $errors = @($findings | Where-Object Severity -eq Error)
    if ($errors.Count -eq 0) {
        $summary += 'No static errors detected.'
    }
    else {
        foreach ($finding in $errors) {
            $location = if ($finding.Path) { "$($finding.Path):$($finding.Line)" } else { 'repository' }
            $summary += "- **$($finding.Repository)** — `$location` — $($finding.Category): $($finding.Message)"
        }
    }

    $summary -join [Environment]::NewLine |
        Set-Content -LiteralPath (Join-Path $OutputPath 'summary.md') -Encoding UTF8

    if ($env:GITHUB_STEP_SUMMARY) {
        Get-Content -LiteralPath (Join-Path $OutputPath 'summary.md') -Raw |
            Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Encoding UTF8
    }

    if ($errors.Count -gt 0) {
        exit 1
    }
}
finally {
    Remove-Item -LiteralPath $workRoot -Recurse -Force -ErrorAction SilentlyContinue
}
