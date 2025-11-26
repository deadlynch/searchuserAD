# Busca abrangente em computadores ativos via AD

param(
    [Parameter(Mandatory=$true)]
    [string]$UsuarioParaPesquisa,
    
    [int]$DiasAtivos = 7,
    [int]$ThreadCount = 50,
    [switch]$QuickScan,
    [string]$OU = "",
    [switch]$ForceAD
)

# Configurações de performance
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

function Get-ActiveComputers {
    param([int]$Dias = 7)
    
    Write-Host "[+] Buscando computadores ativos nos últimos $Dias dias..." -ForegroundColor Green
    
    # Método PRINCIPAL: Via Active Directory
    if ((Get-Module -ListAvailable -Name ActiveDirectory) -or $ForceAD) {
        try {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            
            # CORREÇÃO: Sintaxe correta do filtro LDAP
            $filter = "OperatingSystem -like '*Windows*'"
            
            Write-Host "[+] Consultando Active Directory com filtro: $filter" -ForegroundColor Yellow
            
            # Parâmetros de busca
            $adParams = @{
                Filter = $filter
                Properties = 'Name', 'LastLogonDate', 'IPv4Address', 'OperatingSystem', 'Enabled', 'Created'
            }
            
            # Adiciona OU específica se fornecida
            if ($OU) {
                $adParams['SearchBase'] = $OU
                Write-Host "[+] Buscando na OU: $OU" -ForegroundColor Yellow
            } else {
                # Busca em todo o domínio
                Write-Host "[+] Buscando em todo o domínio..." -ForegroundColor Yellow
            }
            
            $allComputers = Get-ADComputer @adParams | 
                           Where-Object { $_.Enabled -eq $true }
            
            Write-Host "[+] Encontrados $($allComputers.Count) computadores Windows no AD" -ForegroundColor Green
            
            if ($allComputers.Count -eq 0) {
                Write-Host "[-] Nenhum computador encontrado no AD. Verifique as permissões." -ForegroundColor Red
                return @()
            }
            
            # Filtra por data se não for QuickScan
            if (-not $QuickScan) {
                $cutoffDate = (Get-Date).AddDays(-$Dias)
                $activeComputers = $allComputers | Where-Object { 
                    $_.LastLogonDate -ge $cutoffDate -or 
                    $_.LastLogonDate -eq $null -or
                    $_.Created -ge $cutoffDate
                }
                Write-Host "[+] $($activeComputers.Count) computadores ativos nos últimos $Dias dias" -ForegroundColor Green
            } else {
                $activeComputers = $allComputers
                Write-Host "[+] Modo rápido: usando todos os $($activeComputers.Count) computadores" -ForegroundColor Yellow
            }
            
            # Converte para formato padronizado
            $result = $activeComputers | ForEach-Object {
                $priority = 3 # Prioridade padrão (mais baixa)
                
                if ($_.LastLogonDate -ge (Get-Date).AddDays(-1)) { 
                    $priority = 1 # Alta prioridade (últimas 24h)
                } elseif ($_.LastLogonDate -ge (Get-Date).AddDays(-3)) { 
                    $priority = 2 # Média prioridade (últimos 3 dias)
                }
                
                [PSCustomObject]@{
                    ComputerName = $_.Name
                    IPAddress = $_.IPv4Address
                    LastLogon = $_.LastLogonDate
                    Priority = $priority
                    OS = $_.OperatingSystem
                    Enabled = $_.Enabled
                }
            }
            
            Write-Host "[+] Priorizando computadores por atividade recente..." -ForegroundColor Green
            return $result | Sort-Object Priority, LastLogon -Descending
        }
        catch {
            Write-Warning "Erro ao acessar AD: $($_.Exception.Message)"
            Write-Host "[-] Não foi possível acessar o Active Directory" -ForegroundColor Red
            
            # Tenta método alternativo mais simples
            Write-Host "[+] Tentando método alternativo..." -ForegroundColor Yellow
            return Get-ComputersAlternativeMethod
        }
    } else {
        Write-Host "[-] Módulo Active Directory não disponível" -ForegroundColor Red
        Write-Host "[+] Use -ForceAD para tentar forçar o carregamento ou instale o módulo RSAT" -ForegroundColor Yellow
        return Get-ComputersAlternativeMethod
    }
}

function Get-ComputersAlternativeMethod {
    Write-Host "[+] Usando método alternativo para buscar computadores..." -ForegroundColor Yellow
    
    try {
        # Método alternativo usando .NET DirectoryServices
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        $context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain)
        $searcher = New-Object System.DirectoryServices.AccountManagement.PrincipalSearcher
        $computerPrincipal = New-Object System.DirectoryServices.AccountManagement.ComputerPrincipal($context)
        $searcher.QueryFilter = $computerPrincipal
        
        $computers = $searcher.FindAll()
        $computerList = @()
        
        foreach ($computer in $computers) {
            if ($computer.Enabled -eq $true) {
                $computerList += [PSCustomObject]@{
                    ComputerName = $computer.Name
                    IPAddress = "N/A"
                    LastLogon = if ($computer.LastLogon) { $computer.LastLogon } else { $null }
                    Priority = 2
                    OS = "Windows"
                    Enabled = $true
                }
            }
        }
        
        Write-Host "[+] Encontrados $($computerList.Count) computadores via método alternativo" -ForegroundColor Green
        return $computerList
    }
    catch {
        Write-Host "[-] Método alternativo também falhou: $($_.Exception.Message)" -ForegroundColor Red
        
        # Último recurso: busca computadores no domínio via rede
        Write-Host "[+] Tentando descobrir computadores via rede..." -ForegroundColor Yellow
        return Get-NetworkComputers
    }
}

function Get-NetworkComputers {
    $computers = @()
    
    try {
        # Tenta obter computadores do domínio atual
        $domain = $env:USERDNSDOMAIN
        if ($domain) {
            Write-Host "[+] Procurando computadores no domínio $domain via Win32..." -ForegroundColor Yellow
            
            # Método via WMI
            $networkComputers = Get-WmiObject -Class Win32_ComputerSystem -Filter "Domain='$domain'" -ErrorAction SilentlyContinue
            foreach ($comp in $networkComputers) {
                $computers += [PSCustomObject]@{
                    ComputerName = $comp.Name
                    IPAddress = "N/A"
                    LastLogon = Get-Date
                    Priority = 3
                    OS = "Windows"
                    Enabled = $true
                }
            }
        }
    }
    catch {
        # Continua sem falhas
    }
    
    # Adiciona computador local como fallback
    $computers += [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        IPAddress = "N/A"
        LastLogon = Get-Date
        Priority = 1
        OS = "Windows"
        Enabled = $true
    }
    
    Write-Host "[+] Encontrados $($computers.Count) computadores via descoberta de rede" -ForegroundColor Green
    return $computers
}

function Test-ComputerAccess {
    param([string]$ComputerName, [int]$TimeoutMs = 3000)
    
    # Teste múltiplo de conectividade
    try {
        # Teste 1: Ping
        $ping = New-Object System.Net.NetworkInformation.Ping
        $reply = $ping.Send($ComputerName, $TimeoutMs)
        if ($reply.Status -eq 'Success') {
            return $true
        }
    }
    catch {
        # Continua para outros métodos
    }
    
    # Teste 2: Portas comuns
    $commonPorts = @(135, 445, 3389) # RPC, SMB, RDP
    
    foreach ($port in $commonPorts) {
        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $asyncResult = $tcpClient.BeginConnect($ComputerName, $port, $null, $null)
            $wait = $asyncResult.AsyncWaitHandle.WaitOne(1500, $false)
            
            if ($wait -and $tcpClient.Connected) {
                $tcpClient.EndConnect($asyncResult)
                $tcpClient.Close()
                return $true
            }
            $tcpClient.Close()
        }
        catch {
            # Porta fechada, continua
        }
    }
    
    return $false
}

function Get-LoggedOnUserFast {
    param([string]$ComputerName)
    
    # Método 1: Query User (Mais rápido)
    try {
        $sessions = query user /server:$ComputerName 2>$null
        if ($sessions -and $sessions.Length -gt 1) {
            $loggedUsers = @()
            for ($i = 1; $i -lt $sessions.Length; $i++) {
                $line = $sessions[$i].Trim()
                # Parse melhorado da saída do query user
                if ($line -match '^>?(\S+)\s+(\S+)\s+(\d+)\s+(\w+)\s+([\w/]+)\s+(\S+)') {
                    $loggedUsers += [PSCustomObject]@{
                        UserName = $matches[1]
                        ComputerName = $ComputerName
                        SessionName = $matches[2]
                        State = $matches[4]
                        Method = "QueryUser"
                    }
                } elseif ($line -match '^(\S+)\s+(\w+)\s+(\d+\s+\w+)\s+(\S+)') {
                    $loggedUsers += [PSCustomObject]@{
                        UserName = $matches[1]
                        ComputerName = $ComputerName
                        SessionName = $matches[4]
                        State = $matches[2]
                        Method = "QueryUser"
                    }
                }
            }
            return $loggedUsers
        }
    }
    catch {
        # Falha no query user, continua para método alternativo
    }
    
    # Método 2: CIM/WMI (Mais confiável)
    try {
        $logonSessions = Get-CimInstance -ClassName Win32_LogonSession -ComputerName $ComputerName -ErrorAction Stop
        $loggedUsers = @()
        
        foreach ($session in $logonSessions) {
            if ($session.LogonType -eq 2 -or $session.LogonType -eq 10) { # Interativo ou RemoteInteractive
                $logonId = $session.LogonId
                $associatedUsers = Get-CimInstance -ClassName Win32_LoggedOnUser -ComputerName $ComputerName |
                                 Where-Object { $_.Dependent.LogonId -eq $logonId }
                
                foreach ($loggedOnUser in $associatedUsers) {
                    $antecedent = $loggedOnUser.Antecedent
                    if ($antecedent -match 'Domain="([^"]+)",Name="([^"]+)"') {
                        $loggedUsers += [PSCustomObject]@{
                            UserName = "$($Matches[1])\$($Matches[2])"
                            ComputerName = $ComputerName
                            SessionName = "Logon-$logonId"
                            State = "Active"
                            Method = "CIM"
                        }
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
        [int]$MaxThreads = 50
    )
    
    $results = @()
    $counter = 0
    $total = $Computers.Count
    
    Write-Host "[+] Verificando $total computadores..." -ForegroundColor Green
    
    # Processamento em lote sequencial otimizado
    foreach ($computer in $Computers) {
        $counter++
        Write-Progress -Activity "Verificando computadores" -Status "$counter de $total - $($computer.ComputerName)" -PercentComplete (($counter / $total) * 100)
        
        try {
            # Teste rápido de conectividade
            if (Test-ComputerAccess -ComputerName $computer.ComputerName -TimeoutMs 2000) {
                Write-Host "  [+] Conectado: $($computer.ComputerName)" -ForegroundColor Green
                
                $users = Get-LoggedOnUserFast -ComputerName $computer.ComputerName
                if ($users) {
                    foreach ($user in $users) {
                        # Busca flexível pelo usuário
                        $userNameOnly = $user.UserName -replace '^.*\\', ''
                        if ($user.UserName -like "*$UserName*" -or $userNameOnly -like "*$UserName*") {
                            
                            $networkInfo = Get-NetworkInfo -ComputerName $computer.ComputerName
                            
                            $result = [PSCustomObject]@{
                                Usuario = $user.UserName
                                Computador = $computer.ComputerName
                                Dominio = $networkInfo.Domain
                                IP = $networkInfo.IPAddress
                                Sessao = $user.SessionName
                                Estado = $user.State
                                UltimoLogon = $computer.LastLogon
                                Prioridade = $computer.Priority
                                Metodo = $user.Method
                                Timestamp = Get-Date
                            }
                            
                            $results += $result
                            
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
        if ($counter % 5 -eq 0) {
            Start-Sleep -Milliseconds 100
        }
    }
    
    Write-Progress -Activity "Verificando computadores" -Completed
    return $results
}

function Get-NetworkInfo {
    param([string]$ComputerName)
    
    try {
        # Resolução DNS rápida
        $ipAddress = [System.Net.Dns]::GetHostAddresses($ComputerName) | 
                    Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                    Select-Object -First 1 -ExpandProperty IPAddressToString
        
        # Tenta obter informações do computador
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $ComputerName -ErrorAction SilentlyContinue
        
        return @{ 
            IPAddress = if ($ipAddress) { $ipAddress } else { "Não resolvido" }
            Domain = if ($computerSystem) { $computerSystem.Domain } else { "Domínio não acessível" }
        }
    }
    catch {
        return @{ IPAddress = "Erro de resolução"; Domain = "Erro" }
    }
}

# EXECUÇÃO PRINCIPAL
Clear-Host
Write-Host "=== LOCALIZADOR DE USUÁRIOS (VERSÃO AD CORRIGIDA) ===" -ForegroundColor Cyan
Write-Host "=" * 65

# Determina modo de operação
if ($QuickScan) {
    Write-Host "Modo: Busca Rápida (todos os computadores do AD)" -ForegroundColor Yellow
} else {
    Write-Host "Modo: Busca Completa (últimos $DiasAtivos dias)" -ForegroundColor Green
}

Write-Host "Threads: $ThreadCount | Usuário: $UsuarioParaPesquisa" -ForegroundColor Gray
if ($OU) {
    Write-Host "OU específica: $OU" -ForegroundColor Gray
}
Write-Host "=" * 65

$startTime = Get-Date

# Obtém computadores ativos do AD
$activeComputers = Get-ActiveComputers -Dias $DiasAtivos

if ($activeComputers.Count -eq 0) {
    Write-Host "[-] Nenhum computador encontrado para verificação." -ForegroundColor Red
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
Write-Host "Tempo de execução: $($duration.ToString('mm\:ss'))" -ForegroundColor Gray
Write-Host "Computadores no AD: $($activeComputers.Count)" -ForegroundColor Gray
Write-Host "Sessões encontradas: $($results.Count)" -ForegroundColor Gray

if ($results.Count -gt 0) {
    Write-Host "`n[!] USUÁRIO ENCONTRADO EM $($results.Count) LOCAL(IS):" -ForegroundColor Red
    
    $results | Sort-Object Prioridade, UltimoLogon -Descending | Format-Table -AutoSize -Property @(
        @{Name="Usuário"; Expression={$_.Usuario}},
        @{Name="Computador"; Expression={$_.Computador}},
        @{Name="IP"; Expression={$_.IP}},
        @{Name="Domínio"; Expression={$_.Dominio}},
        @{Name="Estado"; Expression={$_.Estado}},
        @{Name="Último Logon PC"; Expression={if($_.UltimoLogon){$_.UltimoLogon.ToString("dd/MM HH:mm")}else{"Nunca"}}}
    )
} else {
    Write-Host "`n[-] Usuário '$UsuarioParaPesquisa' não encontrado em computadores ativos." -ForegroundColor Yellow
}

# Estatísticas
$onlineCount = ($activeComputers | Where-Object { 
    Test-ComputerAccess -ComputerName $_.ComputerName -TimeoutMs 1000 
}).Count

Write-Host "`nEstatísticas:" -ForegroundColor Gray
Write-Host "  • Computadores online: $onlineCount/$($activeComputers.Count)" -ForegroundColor Gray
if ($activeComputers.Count -gt 0) {
    $successRate = [Math]::Round(($onlineCount / $activeComputers.Count) * 100, 1)
    Write-Host "  • Taxa de resposta: $successRate%" -ForegroundColor Gray
}

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

Write-Host "`nBusca concluída!" -ForegroundColor Green
