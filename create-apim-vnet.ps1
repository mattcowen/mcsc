<#
Author: Matt Cowen
Date: Nov 2019

Use at your own risk. No guarantee or warranty of any kind.

This was proof-of-concept activity to deploy an ILB App Gateway and demo
rewriting the path to the backend from /_search/... to /echo/... 

Any other path is black-holed to ensure users only access what we want on the backend.

APIM is only used for the back-end because it was easy to configure and comes with the Echo API.
#>

$gatewayHostname = "mcapim.admuk.net"                 # API gateway host
$portalHostname = "mcapim.portal.admuk.net"               # API developer portal host
$resGroupName = 'apim'
$apimName = "mcapim"
$location = 'North Europe'
$vnetName = 'cowenvnet'
$vnetRg = 'CowenRg'
$appGwSubnetName = "backend2"
$apimSubnetName = "backend"
$pathRulePath = "/_search*"
$convertPath = "/echo/"
$emailAddress = 'you@example.com'
$apimHealthProbeTestPath = "/echo/resource?param1=sample&subscription-key=xxx"

$pwd = ConvertTo-SecureString -String "Azure123456!" -Force -AsPlainText

# my cert is a wildcard *.admuk.net
$gatewayCertCerPath = "C:\certificates\admuk.cer" 
$gatewayCertPfxPath = "C:\certificates\admuk.pfx" 
$portalCertPfxPath = "C:\certificates\admuk.pfx"   


<# create self-signed certs
$gwCrt = New-SelfSignedCertificate `
  -certstorelocation cert:\localmachine\my `
  -dnsname $gatewayHostname

Export-PfxCertificate `
  -cert "cert:\localMachine\my\$($gwCrt.Thumbprint)" `
  -FilePath $gatewayCertPfxPath `
  -Password $pwd

$ptlCrt = New-SelfSignedCertificate `
  -certstorelocation cert:\localmachine\my `
  -dnsname $portalHostname

Export-PfxCertificate `
  -cert "cert:\localMachine\my\$($ptlCrt.Thumbprint)" `
  -FilePath $portalCertPfxPath `
  -Password $pwd

# now export the gateway certificate without private key to get a .cer and store at $gatewayCertCerPath
#>

# if we were using a custom domain to access the backend service then we would need the following hostname config on apim.
# we're using the default azure-api.net 
<#$proxyHostnameConfig = New-AzApiManagementCustomHostnameConfiguration -Hostname $gatewayHostname -HostnameType Proxy `
    -PfxPath $gatewayCertPfxPath -PfxPassword $pwd 

$portalHostnameConfig = New-AzApiManagementCustomHostnameConfiguration -Hostname $portalHostname -HostnameType DeveloperPortal `
    -PfxPath $portalCertPfxPath -PfxPassword $pwd #>

$vnet = Get-AzVirtualNetwork -Name $vnetName -ResourceGroupName $vnetRg
$apimService = Get-AzApiManagement -ResourceGroupName "apim" -Name $apimName -ErrorAction SilentlyContinue -ErrorVariable something1

if($something1){
    $subnet = Get-AzVirtualNetworkSubnetConfig -Name $apimSubnetName -VirtualNetwork $vnet
    $apimVnet = New-AzApiManagementVirtualNetwork -SubnetResourceId $subnet.Id
    $apimService = New-AzApiManagement -Capacity 1 -Sku Developer -Location 'North Europe' -VirtualNetwork $apimVnet -Name $apimName -ResourceGroupName 'apim' `
        -Organization 'MCSC' -AdminEmail $emailAddress -VpnType 'Internal' #-CustomHostnameConfiguration $proxyHostnameConfig, $portalHostnameConfig
}
else
{
    # for when you need a custom domain configured on apim
    #$apimService.ProxyCustomHostnameConfiguration = $proxyHostnameConfig
    #$apimService.PortalCustomHostnameConfiguration = $portalHostnameConfig
    #Set-AzApiManagement -InputObject $apimService
}

#$publicip = Get-AzPublicIpAddress -ResourceGroupName $resGroupName -Name "mcgwip" -ErrorAction SilentlyContinue -ErrorVariable something2
$appgatewaysubnet = Get-AzVirtualNetworkSubnetConfig -Name $appGwSubnetName -VirtualNetwork $vnet

if($something2){
    #$publicip = New-AzPublicIpAddress -ResourceGroupName $resGroupName -name "mcgwip" -location $location -AllocationMethod Dynamic
}

$gipconfig = New-AzApplicationGatewayIPConfiguration -Name "apimAppGw" -Subnet $appgatewaysubnet

$fp01 = New-AzApplicationGatewayFrontendPort -Name "port01"  -Port 443
$fipconfig01 = New-AzApplicationGatewayFrontendIPConfig -Name "privateFrontend" -Subnet $appgatewaysubnet -PrivateIPAddress 10.100.5.5
#$fipconfig02 = New-AzApplicationGatewayFrontendIPConfig -Name "publicFrontend" -PublicIPAddress $publicip

$cert = New-AzApplicationGatewaySslCertificate -Name "gwCert01" -CertificateFile $gatewayCertPfxPath -Password $pwd
$certPortal = New-AzApplicationGatewaySslCertificate -Name "prtlCert02" -CertificateFile $portalCertPfxPath -Password $pwd

$listener = New-AzApplicationGatewayHttpListener -Name "https" -Protocol "Https" -FrontendIPConfiguration $fipconfig01  `
    -FrontendPort $fp01 -SslCertificate $cert -HostName $gatewayHostname  -RequireServerNameIndication true


$apimprobe = New-AzApplicationGatewayProbeConfig -Name "apimproxyprobe" -Protocol "Https" -PickHostNameFromBackendHttpSettings `
    -Path $apimHealthProbeTestPath -Interval 30 -Timeout 30 -UnhealthyThreshold 3

# we don't need an authcert since we're using azure-api.net/azurewebsites.net on the backend so it's already whitelisted
#$authcert = New-AzApplicationGatewayAuthenticationCertificate -Name "whitelistcert1" -CertificateFile $gatewayCertCerPath

$connDraining = New-AzApplicationGatewayConnectionDraining -Enabled $false -DrainTimeoutInSec 10
$apimPoolSetting = New-AzApplicationGatewayBackendHttpSetting -Name "apimPoolSetting" -Port 443 -Protocol "Https" -Path $convertPath  `
   -CookieBasedAffinity "Disabled" -Probe $apimprobe -RequestTimeout 20 -ConnectionDraining $connDraining -PickHostNameFromBackendAddress 

$apimProxyBackendPool = New-AzApplicationGatewayBackendAddressPool -Name "apim" -BackendFqdns "$apimName.azure-api.net"
$apimBlackholeBackendPool = New-AzApplicationGatewayBackendAddressPool -Name "blackhole" -BackendFqdns "$apimName.portal.azure-api.net" # needs to point to an nice error page/response

$gwPathRule = New-AzApplicationGatewayPathRuleConfig -Name "all" -Paths $pathRulePath -BackendHttpSettings $apimPoolSetting -BackendAddressPool $apimProxyBackendPool
$pathCfg = New-AzApplicationGatewayUrlPathMapConfig -Name "pathRule" -PathRules $gwPathRule -DefaultBackendAddressPool $apimBlackholeBackendPool `
    -DefaultBackendHttpSettings $apimPoolSetting # strange there is no Listener parameter like the portal but this works

$rule01 = New-AzApplicationGatewayRequestRoutingRule -Name "path1" -RuleType PathBasedRouting -HttpListener $listener `
    -BackendAddressPool $apimBlackholeBackendPool -BackendHttpSettings $apimPoolSetting -UrlPathMap $pathCfg

$sku = New-AzApplicationGatewaySku -Name "WAF_Medium" -Tier "WAF" -Capacity 1

$config = New-AzApplicationGatewayWebApplicationFirewallConfiguration -Enabled $true -FirewallMode "Detection"


$appgwName = "apim-app-gw2"
$appgw = New-AzApplicationGateway -Name $appgwName -ResourceGroupName $resGroupName -Location $location -BackendAddressPools $apimProxyBackendPool,$apimBlackholeBackendPool `
   -BackendHttpSettingsCollection $apimPoolSetting  -FrontendIpConfigurations $fipconfig01 -UrlPathMaps $pathCfg -GatewayIpConfigurations $gipconfig `
   -FrontendPorts $fp01 -HttpListeners $listener -RequestRoutingRules $rule01 -Sku $sku -WebApplicationFirewallConfig $config `
   -SslCertificates $cert, $certPortal -Probes $apimprobe

