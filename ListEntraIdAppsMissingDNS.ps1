
function missingHTTPUrl {
    param (
        [string]$url
    )
    
    # Check starts with http/s
    $pattern = "^https?://"
    if ($url -notmatch $pattern) {
        return $false
    }
    
    # Try to resolve domain
    try {
        $res = Resolve-DnsName ([System.Uri] $url).Host -ErrorAction Stop
    }
    catch [System.ComponentModel.Win32Exception] {
        return $true
    }
    catch {
        return $false
    }
    
    return $false
}

function getOAuthResourceName {
    param (
        [PSObject]$resources
    )
    
    foreach ($resource in $resources) {
        $ResourceAppId = $resource.ResourceAppId
        $oauth2PermissionScopeIds = $resource.ResourceAccess.Id
        $sp = Get-AzADServicePrincipal -ApplicationId $ResourceAppId
        Write-Host " Resource App Display Name: $($sp.DisplayName), Resource AppId: $($sp.AppId)"
        
        foreach ($oauth2PermissionScopeId in $oauth2PermissionScopeIds) {
            $value = ($sp.Oauth2PermissionScope | Where-Object Id -Match $oauth2PermissionScopeId).value
            $type = ($sp.Oauth2PermissionScope | Where-Object Id -Match $oauth2PermissionScopeId).type
            
            if ($value -eq $null) {
                Write-Host " oauthPermission: (Not an OAuth2 scoped permission), oauthPermissionId: $($oauth2PermissionScopeId)"
            }
            else {
                Write-Host " oauthPermission: $($value) (type: $($type)), oauthPermissionId: $($oauth2PermissionScopeId)"
            }
        }
        Write-Host
    }
}
# Connect to Azure
Connect-AzAccount -AuthScope MicrosoftGraphEndpointResourceId

# Load Application URL data from tenant
$apps = Get-AzADApplication

# Filter apps which have abusable reply URLs defined
$appsAbusableReplyURL = @()

foreach ($app in $apps) {
    # Skip apps which don't have reply URL defined
    if ([string]::IsNullOrEmpty($app.Spa.RedirectUri) -and
        [string]::IsNullOrEmpty($app.PublicClient.RedirectUri) -and
        [string]::IsNullOrEmpty($app.Web.RedirectUri)) {
        continue
    }
    
    # Check if their reply URL's domain is defined and is abusable
    $appAbusableReplyURLs = @()
    
    $app.Spa.RedirectUri | ForEach-Object {
        if (missingHTTPUrl -url $_) {
            $appAbusableReplyURLs += [PSObject]@{ type = "spa"; url = $_; }
        }
    }
    
    $app.PublicClient.RedirectUri | ForEach-Object {
        if (missingHTTPUrl -url $_) {
            $appAbusableReplyURLs += [PSObject]@{ type = "publicClient"; url = $_; }
        }
    }
    
    $app.web.redirectUris | ForEach-Object {
        if ($app.web.ImplicitGrantSetting.EnableAccessTokenIssuance -and
            (missingHTTPUrl -url $_)) {
            $appAbusableReplyURLs += [PSObject]@{ type = "web (implicitGrant Enabled)"; url = $_; }
        }
    }
    
    # Skip apps which don't have abusable URLs
    if ($appAbusableReplyURLs.Count -eq 0) {
        continue
    }
    
    Write-Host "App Display Name: $($app.displayName), AppId: $($app.Appid)"
    Write-Host " Abusable reply URL"
    foreach ($appAbusableReplyURL in $appAbusableReplyURLs) {
        Write-Host " $($appAbusableReplyURL.url) ($($appAbusableReplyURL.type))"
    }
    Write-Host ""
    
    # Write App Permissions
    getOAuthResourceName -resources $app.RequiredResourceAccess
    Write-Host ""
}