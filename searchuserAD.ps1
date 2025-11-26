param(
    [Parameter(Mandatory=$true)]
    [string]$UsuarioParaPesquisa,
    
    [int]$DiasAtivos = 7,
    [int]$ThreadCount = 20,
    [switch]$QuickScan
)

# Configurações de performance
$ErrorActionPreference = 'SilentlyContinue'

function Get-ActiveComputers {
    param([int]$Dias = 7)

    Write-Host "[+] Buscando computadores no AD..." -ForegroundColor Green
    $cutoffDate = (Get-Date).AddDays(-$Dias)

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        Write-Error "Módulo ActiveDirectory não encontrado. Abortando varredura."
        return @()
    }

    # Busca máquinas Windows com propriedades completas
    $computers = Get-ADComputer -Filter "OperatingSystem -like '*Windows*'" `
                -Properties Name, Enabled, LastLogonDate, IPv4Address

    if ($computers.Count -eq 0) {
        Write-Warning "AD retornou zero computadores."
        return @()
    }

    # Filtro de máquinas realmente ativas
    if ($QuickScan) {
        $filtered = $computers | Where-Object { $_.Enabled -eq $true }
    }
    else {
        $filtered = $computers | Where-Object {
            $_.Enabled -eq $true -and $_.LastLogonDate -ge $cutoffDate
        }
    }

    Write-Host "[+] Computadores após filtro: $($filtered.Count)" -ForegroundColor Green

    return $filtered | ForEach-Object {
        [PSCustomObject]@{
            ComputerName = $_.Name
            IPAddress    = $_.IPv4Address
            LastLogon    = $_.LastLogonDate
            Priority     = if ($_.LastLogonDate -ge (Get-Date).AddDays(-1)) {1} else {2}
        }
    } | Sort-Object Priority, LastLogon -Descending
}

function Test-ComputerAccess {
    param([string]$ComputerName, [int]$TimeoutMs = 2000)
    
    try {
        $ping = New-Object System.Net.NetworkInformation.Ping
        $reply = $ping.Send($ComputerName, $TimeoutMs)
        return $reply.Status -eq 'Success'
    }
    catch {
        return $false
    }
}

function Get-LoggedOnUserFast {
    param([string]$ComputerName)

    try {
        $sessions = query user /server:$ComputerName 2>$null
        if ($sessions) {
            $loggedUsers = @()
            for ($i = 1; $i -lt $sessions.Length; $i++) {
                $session = $sessions[$i] -split '\s+'
                if ($session.Count -ge 4) {
                    $loggedUsers += [PSCustomObject]@{
                        UserName = $session[1]
                        ComputerName = $ComputerName
                        SessionName = $session[2]
                        State = $session[4]
                    }
                }
            }
            return $loggedUsers
        }
    }
    catch {}

    # fallback via CIM
    try {
        $logonSessions = Get-CimInstance -ClassName Win32_LogonSession -ComputerName $ComputerName -ErrorAction Stop
        $loggedUsers = @()
        
        foreach ($session in $logonSessions) {
            $logonId = $session.LogonId
            
            $loggedOnUser = Get-CimInstance -ClassName Win32_LoggedOnUser -ComputerName $ComputerName |
                            Where-Object { $_.Dependent.LogonId -eq $logonId }

            if ($loggedOnUser) {
                $antecedent = $loggedOnUser.Antecedent
                if ($antecedent -match 'Domain="([^"]+)",Name="([^"]+)"') {
                    $loggedUsers += [PSCustomObject]@{
                        UserName = "$($Matches[1])\$($Matches[2])"
                        ComputerName = $ComputerName
                        SessionName = "CIM-$logonId"
                        State = "Active"
                    }
                }
            }
        }
        return $loggedUsers
    }
    catch {
        return $null
    }
}

function Invoke-ParallelComputerCheck {
    param(
        [array]$Computers,
        [string]$UserName,
        [int]$MaxThreads = 20
    )
    
    $results = @()
    $counter = 0
    $total = $Computers.Count
    
    Write-Host "[+] Verificando $total computadores..." -ForegroundColor Green
    
    foreach ($computer in $Computers) {
        $counter++
        Write-Progress -Id 1 -Activity "Verificando computadores" -Status "$counter de $total - $($computer.ComputerName)" -PercentComplete (($counter / $total) * 100)
        
        try {
            if (Test-ComputerAccess -ComputerName $computer.ComputerName -TimeoutMs 1500) {
                $users = Get-LoggedOnUserFast -ComputerName $computer.ComputerName
                if ($users) {
                    foreach ($user in $users) {
                        if ($user.UserName -like "*$UserName*") {
                            $networkInfo = Get-NetworkInfo -ComputerName $computer.ComputerName
                            $results += [PSCustomObject]@{
                                Usuario = $user.UserName
                                Computador = $computer.ComputerName
                                Dominio = $networkInfo.Domain
                                IP = $networkInfo.IPAddress
                                Sessao = $user.SessionName
                                Estado = $user.State
                                UltimoLogon = $computer.LastLogon
                                Prioridade = $computer.Priority
                                Timestamp = Get-Date
                            }
                            
                            Write-Host "`n[!] ENCONTRADO: $($user.UserName) em $($computer.ComputerName)" -ForegroundColor Green
                        }
                    }
                }
            }
        }
        catch {}

        Start-Sleep -Milliseconds 100
    }
    
    Write-Progress -Id 1 -Activity "Verificando computadores" -Completed
    return $results
}

function Get-NetworkInfo {
    param([string]$ComputerName)
    
    try {
        $networkInfo = @{}
        
        $ipAddress = [System.Net.Dns]::GetHostAddresses($ComputerName) | 
                    Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                    Select-Object -First 1 -ExpandProperty IPAddressToString
        
        $networkInfo.IPAddress = if ($ipAddress) { $ipAddress } else { "Não resolvido" }
        
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $ComputerName -ErrorAction SilentlyContinue
        $networkInfo.Domain = if ($computerSystem) { $computerSystem.Domain } else { "Domínio não acessível" }
        
        return $networkInfo
    }
    catch {
        return @{ IPAddress = "Erro"; Domain = "Erro" }
    }
}

# Execução principal
Clear-Host
Write-Host "=== LOCALIZADOR DE USUÁRIOS (OTIMIZADO) ===" -ForegroundColor Cyan

if ($QuickScan) {
    Write-Host "Modo: Busca Rápida" -ForegroundColor Gray
} else {
    Write-Host "Modo: Busca Completa" -ForegroundColor Gray
}

Write-Host "Threads: $ThreadCount | Dias ativos: $DiasAtivos" -ForegroundColor Gray
Write-Host "Usuário: $UsuarioParaPesquisa" -ForegroundColor Yellow
Write-Host "=" * 60

$startTime = Get-Date

# Obtém computadores ativos no AD
$activeComputers = Get-ActiveComputers -Dias $DiasAtivos

if ($activeComputers.Count -eq 0) {
    Write-Host "[-] Nenhum computador ativo encontrado." -ForegroundColor Red
    exit 1
}

Write-Host "[+] Iniciando verificação em $($activeComputers.Count) computadores..." -ForegroundColor Green

$results = Invoke-ParallelComputerCheck -Computers $activeComputers -UserName $UsuarioParaPesquisa -MaxThreads $ThreadCount

$endTime = Get-Date
$duration = $endTime - $startTime

Write-Host "`n" + "=" * 80 -ForegroundColor Cyan
Write-Host "RELATÓRIO FINAL" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "Tempo: $($duration.ToString('mm\:ss'))" -ForegroundColor Gray
Write-Host "Computadores verificados: $($activeComputers.Count)" -ForegroundColor Gray
Write-Host "Sessões encontradas: $($results.Count)" -ForegroundColor Gray

if ($results.Count -gt 0) {
    Write-Host "`n[!] USUÁRIO ENCONTRADO:" -ForegroundColor Red
    
    $results | Sort-Object Prioridade, UltimoLogon -Descending | Format-Table -AutoSize -Property @(
        @{Name="Usuário"; Expression={$_.Usuario}},
        @{Name="Computador"; Expression={$_.Computador}},
        @{Name="IP"; Expression={$_.IP}},
        @{Name="Domínio"; Expression={$_.Dominio}},
        @{Name="Sessão"; Expression={$_.Sessao}},
        @{Name="Estado"; Expression={$_.Estado}},
        @{Name="Último Logon"; Expression={$_.UltimoLogon.ToString("dd/MM HH:mm")}}
    )
} else {
    Write-Host "`n[-] Usuário '$UsuarioParaPesquisa' não encontrado." -ForegroundColor Yellow
}

# Estatísticas
$onlineCount = 0
foreach ($computer in $activeComputers) {
    if (Test-ComputerAccess -ComputerName $computer.ComputerName) {
        $onlineCount++
    }
}

Write-Host "`nEstatísticas:" -ForegroundColor Gray
Write-Host "  • Online: $onlineCount/$($activeComputers.Count)" -ForegroundColor Gray

$successRate = [Math]::Round(($onlineCount / $activeComputers.Count) * 100, 1)
Write-Host "  • Taxa de sucesso: $successRate%" -ForegroundColor Gray

Write-Host "`nBusca concluída às $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Green

if ($results.Count -gt 0) {
    $save = Read-Host "`nDeseja salvar os resultados em CSV? (S/N)"
    if ($save -match '^[sS]$') {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $filename = "Resultado_$($UsuarioParaPesquisa)_$timestamp.csv"
        $results | Export-Csv -Path $filename -NoTypeInformation -Encoding UTF8
        Write-Host "Salvo em: $filename" -ForegroundColor Green
    }
}
