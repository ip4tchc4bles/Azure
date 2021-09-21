
Install-Module -Name Az -Force
Import-Module -Name Az -Force
#Install-Module -Name MSOnline -Force
#Import-Module -Name MSOnline -Force
#Install-Module -Name ExchangeOnlineManagement -Force
#Import-Module -Name ExchangeOnlineManagement -Force



#TODO:
####MFA check
#Get-MsolUser -all -EnabledFilter EnabledOnly | select DisplayName,UserPrincipalName,@{N="MFA Status"; E={ if( $_.StrongAuthenticationMethods.IsDefault -eq $true) {($_.StrongAuthenticationMethods | Where IsDefault -eq $True).MethodType} else { "Disabled"}}} | FT -AutoSize


####Check for legacy auth protocols ie IMAP/POP
#Get-CASMailboxPlan -Identity ExchangeOnlineEnterprise

####Shared mailbox logon
#Get-EXOMailbox -Filter {(RecipientTypeDetails -eq "SharedMailbox") -or (RecipientTypeDetails -eq "RoomMailbox") -or (RecipientTypeDetails -eq "EquipmentMailbox")} | ft


#Get-AzKeyVault
#Get-AzAutomationAccount
#Get-AzFunctionApp 

Write-Output "[*] Ensuring TLSv1.2 is used"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Output "[*] If MFA is not required the above connections should work fine. If Modern Auth is required you will be prompted."
$Credential = Get-Credential -Message "Enter your Azure credentials" -UserName "$env:USERDNSDOMAIN\$env:USERNAME"

Write-Output "[*] Connecting to Azure and Office365"
Connect-AzAccount -Credential $Credential
#Connect-MsolService -Credential $Credential
#Connect-ExchangeOnline -Credential $Credential

$SaveInfo = Read-Host -Prompt "Define output path. EXAMPLE: C:\Derp\enum.txt"
If (Test-Path -Path $SaveInfo)
{

    Write-Warning "This file already exists. Delete it and define the location again or choose a different file name"
    $SaveInfo = Read-Host -Prompt "Define the absoulte path to save the information that will be obtained. EXAMPLE: C:\Derp\enum2.txt"

}  

New-Item -Path $SaveInfo -ItemType File -Force

$AzureContexts = Get-AzContext -ListAvailable
$TenantId = $AzureContexts.Tenant.id
Write-Output "======================================================" | Add-Content -Path $SaveInfo -PassThru
Write-Output "|                  AZURE CONTEXTS                    |" | Add-Content -Path $SaveInfo -PassThru
Write-Output "======================================================" | Add-Content -Path $SaveInfo -PassThru
$AzureContexts | Format-List | Out-String | Add-Content -Path $SaveInfo -PassThru

Write-Output "======================================================" | Add-Content -Path $SaveInfo -PassThru
Write-Output "|             ORGANIZATION INFORMATION               |" | Add-Content -Path $SaveInfo -PassThru
Write-Output "======================================================" | Add-Content -Path $SaveInfo -PassThru
Get-MSolCompanyInformation | Out-String | Add-Content -Path $SaveInfo -PassThru

Write-Output "======================================================" | Add-Content -Path $SaveInfo -PassThru
Write-Output "|            GLOBAL ADMINISTRATORS LIST              |" | Add-Content -Path $SaveInfo -PassThru
Write-Output "======================================================" | Add-Content -Path $SaveInfo -PassThru
$Role = Get-MsolRole -RoleName "Company Administrator"
Get-MsolRoleMember -RoleObjectId $Role.ObjectId | Select-Object -Property DisplayName,EmailAddress,ObjectId,RoleMemberType | Format-Table -AutoSize | Out-String | Add-Content -Path $SaveInfo -PassThru

Write-Output "`n======================================================" | Add-Content -Path $SaveInfo -PassThru
Write-Output "|                SERVICE PRINCIPALS                  |" | Add-Content -Path $SaveInfo -PassThru
Write-Output "======================================================" | Add-Content -Path $SaveInfo -PassThru
Get-MsolServicePrincipal -all | Select-Object -Property DisplayName,AccountEnabled,ObjectId,TrustedForDelegation | Format-Table -AutoSize | Out-String | Add-Content -Path $SaveInfo -PassThru

Write-Output "======================================================" | Add-Content -Path $SaveInfo -PassThru
Write-Output "|               AZURE SUBSCRIPTIONS                  |" | Add-Content -Path $SaveInfo -PassThru
Write-Output "======================================================" | Add-Content -Path $SaveInfo -PassThru
$AzSubscription = Get-AzSubscription -SubscriptionName $AzureContexts.SubscriptionName
$AzSubscription | Format-Table -AutoSize | Out-String | Add-Content -Path $SaveInfo -PassThru


Write-Output "======================================================" | Add-Content -Path $SaveInfo -PassThru
Write-Output "|                 AZURE STORAGE                      |" | Add-Content -Path $SaveInfo -PassThru
Write-Output "======================================================" | Add-Content -Path $SaveInfo -PassThru


$SAs = Get-AzStorageAccount

    $SAs  | Sort-Object -Property Kind,ResourceGroupName |Format-Table -AutoSize | Out-String | Add-Content -Path $SaveInfo -PassThru


    foreach ($sa in $SAs)
    {

        $accountName = $sa.StorageAccountName
        $context = New-AzStorageContext -StorageAccountName $accountName
        Write-Output "==== Listing Storage Account Details: $($context.Name) ===="
        echo $context
        $containers = Get-AzStorageContainer -Context $context
    
    
        foreach($container in $containers)
        {
            Write-Output "==== Blobs in Container: $($container.Name) ===="
            Get-AzStorageBlob -Context $context -Container $container.Name | 
            format-table Name, Length, ContentType, LastModified -auto
        }
    }


Write-Output "======================================================" | Add-Content -Path $SaveInfo -PassThru
Write-Output "|                   AZURE WEB APPS                   |" | Add-Content -Path $SaveInfo -PassThru
Write-Output "======================================================" | Add-Content -Path $SaveInfo -PassThru

$AzureResourceGroups = Get-AzWebApp | Select-Object -Property Name,Id,State,Hostnames,AzureStorageAccounts,GitRemotePassword,ResourceGroup | Out-String | Add-Content -Path $SaveInfo -PassThru

    $AzureSQL = Get-AzSQLServer
    If ($AzureSQL)
    {

        Write-Output "======================================================" | Add-Content -Path $SaveInfo -PassThru
        Write-Output "|                 AZURE SQL SERVERS                  |" | Add-Content -Path $SaveInfo -PassThru
        Write-Output "======================================================" | Add-Content -Path $SaveInfo -PassThru
        $AzureSQL | Out-String | Add-Content -Path $SaveInfo -PassThru

        ForEach ($Asql in $AzureSQL)
        {

            Write-Output "--------------- Azure SQL Database ---------------" | Add-Content -Path $SaveInfo -PassThru
            Get-AzSqlDatabase -ServerName $Asql.ServerName -ResourceGroupName $Asql.ResourceGroupName | Out-String | Add-Content -Path $SaveInfo -PassThru

            Write-Output "------------ Azure SQL Firewall Rules ------------" | Add-Content -Path $SaveInfo -PassThru
            Get-AzSqlServerFirewallRule –ServerName $Asql.ServerName -ResourceGroupName $Asql.ResourceGroupName | Out-String | Add-Content -Path $SaveInfo -PassThru

           # Write-Output "---------------- Azure SQL Admins ----------------" | Add-Content -Path $SaveInfo -PassThru
           # Get-AzSqlServerActiveDirectoryAdminstrator -ServerName $Asql.ServerName -ResourceGroupName $Asql.ResourceGroupName | Out-String | Add-Content -Path $SaveInfo -PassThru

            #Write-Output "--------------------------------------------------" | Add-Content -Path $SaveInfo -PassThru

        }  # End ForEach

    }  # End If

    $AzureVMs = Get-AzVM
    If ($AzureVMs)
    {

        Write-Output "======================================================" | Add-Content -Path $SaveInfo -PassThru
        Write-Output "|                     AZURE VMs                      |" | Add-Content -Path $SaveInfo -PassThru
        Write-Output "======================================================" | Add-Content -Path $SaveInfo -PassThru

        $AzureVMs | ForEach-Object { Get-AzVM -Name $_.Name } | Out-String | Add-Content -Path $SaveInfo -PassThru

    }  # End If

    Write-Output "======================================================" | Add-Content -Path $SaveInfo -PassThru
    Write-Output "|             AZURE Virtual Network Info             |" | Add-Content -Path $SaveInfo -PassThru
    Write-Output "======================================================" | Add-Content -Path $SaveInfo -PassThru
    Get-AzVirtualNetwork | Out-String | Add-Content -Path $SaveInfo -PassThru
    Get-AzPublicIpAddress | Select-Object -Property PublicIpAllocationMethod,Name,IpAddress| Out-String | Add-Content -Path $SaveInfo -PassThru
    #Get-AzExpressRouteCircuit | Out-String | Add-Content -Path $SaveInfo -PassThru
    #Get-AzVpnConnection | Out-String | Add-Content -Path $SaveInfo -PassThru



$AzAdApplication = Get-AzAdApplication
If ($AzAdApplication)
{

    Write-Output "======================================================" | Add-Content -Path $SaveInfo -PassThru
    Write-Output "|      AZURE SSO INTEGRATION AND CUSTOM APPS         |" | Add-Content -Path $SaveInfo -PassThru
    Write-Output "======================================================" | Add-Content -Path $SaveInfo -PassThru
    $AzAdApplication | Select-Object -Property DisplayName,ObjectId,IdentifierUris,HomePage,ReplyUrls,ObjectType | Format-Table -AutoSize | Out-String | Add-Content -Path $SaveInfo -PassThru

}  # End If

Write-Output "======================================================" | Add-Content -Path $SaveInfo -PassThru
Write-Output "|                   Encryption                        |" | Add-Content -Path $SaveInfo -PassThru
Write-Output "======================================================" | Add-Content -Path $SaveInfo -PassThru


##Print Storage Account Encryption
$SAs = Get-AzStorageAccount

    foreach ($sa in $SAs)
    {

    $accountName = $sa.StorageAccountName
	$rgn = $sa.ResourceGroupName
	(Get-AzResource -ResourceGroupName $rgn -ResourceType Microsoft.Storage/storageAccounts -Name $accountName).Properties.encryption  | ConvertTo-Json
    }


##Print Storage Account Network Configs###
#Checks:
#Storage accounts should restrict network access using virtual network rules
#Storage account public access should be disallowed
#Secure transfer to storage accounts should be enabled
#Storage account should use a private link connection



    foreach ($sa in $SAs)
    {

    $accountName = $sa.StorageAccountName
	$rgn = $sa.ResourceGroupName
    Write-Output "==== Listing Storage Account Network : $($accountName) ===="
    Get-AzStorageAccountNetworkRuleSet  -ResourceGroupName $rgn -AccountName $accountName
    
    }

##Print HTTPSOnlyTraffic
Get-AzStorageAccount |Sort-Object -Property EnableHttpsTrafficOnly
Get-AzStorageAccount |Select-Object -Property StorageAccountName,ResourceGroupName,EnableHttpsTrafficOnly | Sort-Object

##List  Network Security Rule Configs

$SGs = Get-AzNetworkSecurityGroup 
    
    foreach ($sg in $SGs)
    {

    $groupName = $sg.ResourceGroupName
	$sgName = $sg.Name
	Get-AzNetworkSecurityGroup -Name $sgName -ResourceGroupName $groupName | Get-AzNetworkSecurityRuleConfig
    }

 #Get-AzPublicIpAddress | Select-Object -Property IpAddress,ResourceGroupName
Get-AzPublicIpAddress | Select-Object -Property IpAddress,ResourceGroupName
Get-AzPublicIpAddress | Select-Object -Property IpAddress,ResourceGroupName
Get-AzPublicIpAddress | Select-Object -Property IpAddress,ResourceGroupName
Get-AzPublicIpAddress | Select-Object -Property IpAddress,ResourceGroupName
Get-AzPublicIpAddress | Select-Object -Property IpAddress,ResourceGroupName
Get-AzPublicIpAddress | Select-Object -Property IpAddress,ResourceGroupName
Get-AzPublicIpAddress | Select-Object -Property IpAddress,ResourceGroupName
Get-AzPublicIpAddress | Select-Object -Property IpAddress,ResourceGroupName
Get-AzPublicIpAddress | Select-Object -Property IpAddress,ResourceGroupName
Get-AzPublicIpAddress | Select-Object -Property IpAddress,ResourceGroupName
Get-AzPublicIpAddress | Select-Object -Property IpAddress,ResourceGroupName
Get-AzPublicIpAddress | Select-Object -Property IpAddress,ResourceGroupName
Get-AzPublicIpAddress | Select-Object -Property IpAddress,ResourceGroupName
Get-AzPublicIpAddress | Select-Object -Property IpAddress,ResourceGroupName
Get-AzPublicIpAddress | Select-Object -Property IpAddress,ResourceGroupName
Get-AzPublicIpAddress | Select-Object -Property IpAddress,ResourceGroupName
Get-AzPublicIpAddress | Select-Object -Property IpAddress,ResourceGroupName
Get-AzPublicIpAddress | Select-Object -Property IpAddress,ResourceGroupName
Get-AzPublicIpAddress | Select-Object -Property IpAddress,ResourceGroupName
Get-AzPublicIpAddress | Select-Object -Property IpAddress,ResourceGroupName

 ##Pull WebApps HTTPS Enabled
 Get-AzWebApp | Select-Object -Property ResourceGroup,DefaultHostname,HTTPSOnly
