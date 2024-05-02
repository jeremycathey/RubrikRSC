<#
.SYNOPSIS
Install the Rubrik Backup Service on a remote machine

.DESCRIPTION
Script will download the Rubrik Backup Service from the RubrikCluster provided. The script will then push the msi, perform a quiet install 
and then configure the service to start under a specific service account. 

.PARAMETER RubrikCluster
Represents the IP Address or Name of the Rubrik Cluster

.PARAMETER OutFile
Download location of the RubrikBackupService.zip from the RubrikCluster

.PARAMETER ComputerName
Server to install the Rubrik Backup Service On

.EXAMPLE
.\Install-RubrikBackupService.ps1 -RubrikCluster 172.21.8.51 -computername cl-sql2012-1a

.NOTES
    Name:               Install Rubrik Backup Service
    Created:            1/03/2019
    Author:             Chris Lumnah
   
#>



param(
    # Rubrik Cluster name or ip address
    [Parameter(Mandatory=$true)]
    [string]$RubrikCluster,
    
    # Computer(s) that should have the Rubrik Backup Service installed onto and then added into Rubrik
    [Parameter(Mandatory=$true)]
    [String[]]$ComputerName,

    # Credential to run the Rubrik Backup Service on the Computer
    [Parameter(Mandatory=$false)]
    [pscredential]$RBSCredential,

    # Parameter help description
    [Parameter(Mandatory=$false)]
    [string]$OutFile = "c:\temp\RubrikBackupService.zip"

    
)

#change me to the write ID/Secret for you
$serviceAccount_ID = "User:::e894ff06-7117-4c1f-8d87-b53a9506a713"
$serviceAccount_secret = "Hgj9PFzB7ppeIQ5j6g5iFEhm3s+txQthMbj/idgwfo506Efxx0nEsYtGutx+mQrsodbJySEgK5e9hwpOlcj/"

if ($RBSCredential){
    $RubrikServiceAccount = $RBSCredential    
}
else{
    $RubrikServiceAccount = Get-Credential -UserName "$($env:UserDomain)\Rubrik$" -Message "Enter user name and password for the service account that will run the Rubrik Backup Service"
}
# Function to Connect to RSC and Get API Token From serviceAccountId and secret
function Connect-CDM {
        param( 
	    [Parameter(Mandatory=$true)] 
	    [String]$ClusterIP,
	    [Parameter(Mandatory=$true)] 
	    [String]$serviceAccountId,
	    [Parameter(Mandatory=$true)] 
	    [String]$secret
	) 
   
    $SessionUrl = "https://$($RubrikCluster)/api/v1/service_account/session"

    $Payload = @{
        "serviceAccountId"     = $serviceAccountId
        "secret" = $secret
        "name"          = "Service Account"
    } | ConvertTo-Json
    $Headers = @{
        'Content-Type' = 'application/json;charset=UTF-8'
        'Accept'       = 'application/json, text/plain'
    }
    $Response = Invoke-RestMethod -Uri $SessionUrl -Method Post -Headers $Headers -Body $Payload # -SkipCertificateCheck
    if (-not $Response.token) {
        Write-Host "Authentication failed!"
        return $null
    }
    $AccessToken = $Response.token

    $CDMConnect = @{
        'Token'   = $AccessToken
        'Headers' = @{
            'Content-Type'  = 'application/json'
            'Accept'        = 'application/json'
            'Authorization' = "Bearer $AccessToken"
        }
    }
    Write-Host "Connected to RSC."
    return $CDMConnect
}

$OutputPath = ".\MOF\"
#region Download the Rubrik Connector 
$url =  "https://$($RubrikCluster)/connector/RubrikBackupService.zip"

add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $url -OutFile $OutFile
#endregion

configuration RubrikService{
    param( 
        [Parameter(Mandatory=$true)] 
        [String]$Server
    ) 
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Node $Server{
        ServiceSet Rubrik{
            Name        = "Rubrik Backup Service"
            StartupType = "Automatic"
            State       = "Running"
            Credential  = $Node.RubrikServiceAccount
        }
    }
}

configuration LocalAdministrators{
    param( 
	    [Parameter(Mandatory=$true)] 
	    [String]$Server
	) 
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Node $Server{
        GroupSet LocalAdminTest
        {
            GroupName        = "Administrators"
            Ensure           = "Present"
            MembersToInclude = $Node.RubrikServiceAccount.UserName
        }
    }
}

#validating the Servername and if it is online
$ValidComputerList=@()
foreach($Computer in $ComputerName){
    $isValidComputer = (Test-Connection -ComputerName $Computer -Count 1 -ErrorAction SilentlyContinue)
    if ($isValidComputer){
        Write-Verbose "$Computer, is up"
        $ValidComputerList +=$isValidComputer | ForEach-Object{ [System.Net.Dns]::Resolve($($_.ProtocolAddress)).HostName}
    }
    else{
        Write-Warning "Could not connect to server $Computer, the RBS will not be installed on this server!" 
    }  
}

foreach($Computer in $ValidComputerList){
    $Computer
    #region Push the RubrikBackupService.zip to remote computer
    if (Test-Path -Path $OutFile)
    {
        $Destination = "\\$($Computer)\C$\Temp\" #RubrikBackupService.zip"
        if (!(test-path -path $Destination))
        {
            New-Item -Path $Destination -ItemType Directory
        }
        $Destination = "\\$($Computer)\C$\Temp\RubrikBackupService.zip"
        Copy-Item -Path $OutFile -Destination $Destination -Force
    }
    #endregion

    #region Unzip the RubrikBackupService on the remote computer
    $Session = New-PSSession -ComputerName $Computer
    Enter-PSSession -Session $Session

    Expand-Archive -LiteralPath $OutFile -DestinationPath "\\$($Computer)\C$\Temp\RubrikBackupService" -Force

    Exit-PSSession
    #endregion

    #region Install the RBS on the Remote Computer
    Invoke-Command -ComputerName $Computer -ScriptBlock {
        Start-Process -FilePath "C:\Temp\RubrikBackupService\RubrikBackupService.msi" -ArgumentList "/quiet" -Wait
    }
    #endregion

    $ConfigurationData = @{
        AllNodes = @(
            @{
                NodeName = $Computer
                PSDscAllowPlainTextPassword = $true
                PSDscAllowDomainUser =$true
                RubrikServiceAccount = $RubrikServiceAccount
            }
        )
    }
}
    # Function to connect to RSC using service account JSON file


    #Configure the Local Administrators
    LocalAdministrators -Server $Computer -ConfigurationData $ConfigurationData -OutputPath $OutputPath 
    Start-DscConfiguration  -ComputerName $Computer -Path $OutputPath -Verbose -Wait -Force

    #Configure the Rubrik Backup Service
    RubrikService -Server $Computer -ConfigurationData $ConfigurationData -OutputPath $OutputPath 
    Start-DscConfiguration  -ComputerName $Computer -Path $OutputPath -Verbose -Wait -Force

    Get-Service -Name "Rubrik Backup Service" -ComputerName $Computer | Stop-Service 
    Get-Service -Name "Rubrik Backup Service" -ComputerName $Computer | Start-Service

    # Connect to CDM and get API Access Token
    $auth = Connect-CDM -ClusterIP $RubrikCluster -serviceAccountId $serviceAccount_ID -secret $serviceAccount_secret

    $hostAPIURL = "https://$($RubrikCluster)/api/v1/host"
    $HostPayload = @{
        "hostname" = $Computer
        "hasAgent" = $true
        "isOracleHost" = $false
    } | ConvertTo-Json

    $Response = Invoke-RestMethod -Uri $hostAPIURL -Method Post -Headers $auth.Headers -Body $HostPayload -SkipCertificateCheck