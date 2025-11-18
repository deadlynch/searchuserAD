# Script otimizado para Localizar Usuários Logados
# Foca em computadores ativos nos últimos 7 dias

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
    
    $activeComputers = @()
    $cutoffDate = (Get-Date).AddDays(-$Dias)
    
    Write-Host "[+] Buscando computadores ativos nos últimos $Dias dias..." -ForegroundColor Green
    
    # Método 1: Via Active Directory (mais eficiente)
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        try {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            
            $filter = "OperatingSystem -like '*Windows*' -and Enabled -eq 'true'"
            if (-not $QuickScan) {
                $filter += " -and LastLogonDate -ge '$cutoffDate'"
            }
            
            $adParams = @{
                Filter = $filter
                Properties = 'Name', 'LastLogonDate', 'IPv4Address'
            }
            
            $computers = Get-ADComputer @adParams | 
                        Select-Object Name, LastLogonDate, IPv4Address |
                        Sort-Object LastLogonDate -Descending
            
            Write-Host "[+] Encontrados $($computers.Count) computadores Windows ativos no AD" -ForegroundColor Green
            
            # Prioriza computadores com logon recente
            $activeComputers = $computers | ForEach-Object {
                [PSCustomObject]@{
                    ComputerName = $_.Name
                    IPAddress = $_.IPv4Address
                    LastLogon = $_.LastLogonDate
                    Priority = if ($_.LastLogonDate -ge (Get-Date).AddDays(-1)) { 1 } else { 2 }
                }
            }
        }
        catch {
            Write-Warning "Erro ao acessar AD: $($_.Exception.Message)"
        }
    }
    
    # Método 2: Se AD não disponível, usa lista local otimizada
    if ($activeComputers.Count -eq 0) {
        Write-Host "[+] Usando lista local de computadores..." -ForegroundColor Yellow
        
        $localComputers = @(
            $env:COMPUTERNAME,
            "localhost"
        )
        
        # Adiciona computadores comuns do ambiente
        $commonServers = @("SRV-01", "SRV-02", "WS-01", "WS-02") # Ajuste conforme necessário
        
        $activeComputers = $localComputers + $commonServers | ForEach-Object {
            [PSCustomObject]@{
                ComputerName = $_
                IPAddress = "N/A"
                LastLogon = Get-Date
                Priority = 1
            }
        }
    }
    
    return $activeComputers | Sort-Object Priority, LastLogon -Descending
}

function Test-ComputerAccess {
    param([string]$ComputerName, [int]$TimeoutMs = 2000)
    
    # Teste rápido de conectividade
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
        # Método mais rápido usando query user
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
    catch {
        # Método alternativo usando CIM (mais lento mas mais confiável)
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
    return $null
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
    
    Write-Host "[+] Verificando $total computadores em lotes de $MaxThreads..." -ForegroundColor Green
    
    # Processamento em lote sequencial (mais estável que threads)
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
                            
                            # Mostra resultado imediatamente
                            Write-Host "`n[!] ENCONTRADO: $($user.UserName) em $($computer.ComputerName)" -ForegroundColor Green
                        }
                    }
                }
            }
        }
        catch {
            # Continua para o próximo computador em caso de erro
            continue
        }
        
        # Pequena pausa para não sobrecarregar a rede
        Start-Sleep -Milliseconds 100
    }
    
    Write-Progress -Id 1 -Activity "Verificando computadores" -Completed
    return $results
}

function Get-NetworkInfo {
    param([string]$ComputerName)
    
    try {
        $networkInfo = @{}
        
        # Resolução DNS rápida
        $ipAddress = [System.Net.Dns]::GetHostAddresses($ComputerName) | 
                    Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                    Select-Object -First 1 -ExpandProperty IPAddressToString
        
        $networkInfo.IPAddress = if ($ipAddress) { $ipAddress } else { "Não resolvido" }
        
        # Informações do computador
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

# Determina modo de operação
if ($QuickScan) {
    Write-Host "Modo: Busca Rápida" -ForegroundColor Gray
} else {
    Write-Host "Modo: Busca Completa" -ForegroundColor Gray
}

Write-Host "Threads: $ThreadCount | Dias ativos: $DiasAtivos" -ForegroundColor Gray
Write-Host "Usuário: $UsuarioParaPesquisa" -ForegroundColor Yellow
Write-Host "=" * 60

$startTime = Get-Date

# Obtém computadores ativos
$activeComputers = Get-ActiveComputers -Dias $DiasAtivos

if ($activeComputers.Count -eq 0) {
    Write-Host "[-] Nenhum computador ativo encontrado para verificação." -ForegroundColor Red
    exit 1
}

Write-Host "[+] Iniciando verificação em $($activeComputers.Count) computadores..." -ForegroundColor Green

# Executa verificação
$results = Invoke-ParallelComputerCheck -Computers $activeComputers -UserName $UsuarioParaPesquisa -MaxThreads $ThreadCount

$endTime = Get-Date
$duration = $endTime - $startTime

# Exibe resultados
Write-Host "`n" + "=" * 80 -ForegroundColor Cyan
Write-Host "RELATÓRIO FINAL" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "Tempo de execução: $($duration.ToString('mm\:ss')) minutos" -ForegroundColor Gray
Write-Host "Computadores verificados: $($activeComputers.Count)" -ForegroundColor Gray
Write-Host "Sessões encontradas: $($results.Count)" -ForegroundColor Gray

if ($results.Count -gt 0) {
    Write-Host "`n[!] USUÁRIO ENCONTRADO EM $($results.Count) LOCAL(IS):" -ForegroundColor Red
    
    $results | Sort-Object Prioridade, UltimoLogon -Descending | Format-Table -AutoSize -Property @(
        @{Name="Usuário"; Expression={$_.Usuario}},
        @{Name="Computador"; Expression={$_.Computador}},
        @{Name="IP"; Expression={$_.IP}},
        @{Name="Domínio"; Expression={$_.Dominio}},
        @{Name="Sessão"; Expression={$_.Sessao}},
        @{Name="Estado"; Expression={$_.Estado}},
        @{Name="Último Logon PC"; Expression={$_.UltimoLogon.ToString("dd/MM HH:mm")}}
    )
} else {
    Write-Host "`n[-] Usuário '$UsuarioParaPesquisa' não encontrado em computadores ativos." -ForegroundColor Yellow
}

# Estatísticas
$onlineCount = 0
foreach ($computer in $activeComputers) {
    if (Test-ComputerAccess -ComputerName $computer.ComputerName) {
        $onlineCount++
    }
}

Write-Host "`nEstatísticas:" -ForegroundColor Gray
Write-Host "  • Computadores online: $onlineCount/$($activeComputers.Count)" -ForegroundColor Gray
if ($activeComputers.Count -gt 0) {
    $successRate = [Math]::Round(($onlineCount / $activeComputers.Count) * 100, 1)
    Write-Host "  • Taxa de sucesso: $successRate%" -ForegroundColor Gray
}

$endTimeFormatted = Get-Date -Format "HH:mm:ss"
Write-Host "`nBusca concluída às $endTimeFormatted" -ForegroundColor Green

# Opção para salvar resultados
if ($results.Count -gt 0) {
    $save = Read-Host "`nDeseja salvar os resultados em um arquivo? (S/N)"
    if ($save -eq 'S' -or $save -eq 's') {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $filename = "Resultado_$($UsuarioParaPesquisa)_$timestamp.csv"
        $results | Export-Csv -Path $filename -NoTypeInformation -Encoding UTF8
        Write-Host "Resultados salvos em: $filename" -ForegroundColor Green
    }
}
