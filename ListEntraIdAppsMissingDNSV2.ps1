
 
# This script scans Azure AD applications for security vulnerabilities in redirect URLs
# that could lead to tenant takeover attacks through domain hijacking and misconfigurations.

# SECURITY VALIDATION FUNCTIONS

# DNS Resolution Validation - Detects unresolvable domains that attackers could register
function missingHTTPUrl {
    param (
        [string]$url
    )
    
    # Check starts with http/s
    $pattern = "^https?://"
    if ($url -notmatch $pattern) {
        return $false
    }
    
    try {
        $uri = [System.Uri]$url
        $urlHost = $uri.Host
        
        # Check for localhost/loopback addresses (potential security risk in production)
        if ($urlHost -match "^(localhost|127\.0\.0\.1|::1)$") {
            Write-Host "Warning: Localhost/loopback address detected: $urlHost"
            return $true
        }
        
        # Check for private IP addresses
        if ($urlHost -match "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)") {
            Write-Host "Warning: Private IP address detected: $urlHost"
            return $true
        }
        
        # Check for wildcards in domain
        if ($urlHost -match "\*") {
            Write-Host "Warning: Wildcard domain detected: $urlHost"
            return $true
        }
        
        # Attempt DNS resolution
        $null = [System.Net.Dns]::GetHostAddresses($urlHost)
        return $false  # Domain resolves successfully
    }
    catch {
        Write-Host "Failed to resolve domain for ${url}: $($_.Exception.Message)"
        return $true   # Domain doesn't resolve
    }
    
    return $false
}

# Insecure Protocol Detection - Identifies HTTP URLs vulnerable to interception
function isInsecureHTTP {
    param (
        [string]$url
    )
    
    # Check if URL uses HTTP instead of HTTPS
    if ($url -match "^http://") {
        return $true
    }
    return $false
}

# Permission Analysis - Extracts OAuth2 scopes and resource access details
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
            
            if ($null -eq $value) {
                Write-Host " oauthPermission: (Not an OAuth2 scoped permission), oauthPermissionId: $($oauth2PermissionScopeId)"
            }
            else {
                Write-Host " oauthPermission: $($value) (type: $($type)), oauthPermissionId: $($oauth2PermissionScopeId)"
            }
        }
        Write-Host
    }
}

# MAIN SECURITY SCAN EXECUTION

# Connect to Azure
# Connect-AzAccount -AuthScope MicrosoftGraphEndpointResourceId

Write-Host "Listing Entra ID Apps with abusable Reply URLs (HTTP/S URL defined but domain not resolvable)"
Write-Host "---------------------------------------------------------------------"

# Load Application URL data from tenant
$apps = Get-AzADApplication

# Initialize results array for CSV export
$results = @()

# Progress tracking
$totalApps = $apps.Count
$currentApp = 0

foreach ($app in $apps) {
    $currentApp++
    $percentComplete = [int](($currentApp / $totalApps) * 100)
    Write-Progress -Activity "Checking Entra ID Apps" -Status "$currentApp of $totalApps" -PercentComplete $percentComplete
    Write-Host "Checking App Display Name: $($app.displayName), AppId: $($app.Appid)"

    # Skip apps which don't have reply URL defined
    if ([string]::IsNullOrEmpty($app.Spa.RedirectUri) -and
        [string]::IsNullOrEmpty($app.PublicClient.RedirectUri) -and
        [string]::IsNullOrEmpty($app.Web.RedirectUri)) {
        Write-Host " No reply URL defined, skipping"
        continue
    }
    
    # Check if their reply URL's domain is defined and is abusable (DNS Resolution Validation)
    $appAbusableReplyURLs = @()
    $insecureHttpUrls = @()
    
    # Validate SPA (Single Page Application) redirect URIs
    $app.Spa.RedirectUri | ForEach-Object {
        if (missingHTTPUrl -url $_) {
            $appAbusableReplyURLs += [PSObject]@{ type = "spa"; url = $_; }
        }
        if (isInsecureHTTP -url $_) {
            $insecureHttpUrls += [PSObject]@{ type = "spa"; url = $_; }
        }
    }
    
    # Validate Public Client redirect URIs
    $app.PublicClient.RedirectUri | ForEach-Object {
        if (missingHTTPUrl -url $_) {
            $appAbusableReplyURLs += [PSObject]@{ type = "publicClient"; url = $_; }
        }
        if (isInsecureHTTP -url $_) {
            $insecureHttpUrls += [PSObject]@{ type = "publicClient"; url = $_; }
        }
    }
    
    # Validate Web Application redirect URIs (check implicit grant settings)
    $app.web.redirectUris | ForEach-Object {
        if ($app.web.ImplicitGrantSetting.EnableAccessTokenIssuance -and
            (missingHTTPUrl -url $_)) {
            $appAbusableReplyURLs += [PSObject]@{ type = "web (implicitGrant Enabled)"; url = $_; }
        }
        if (isInsecureHTTP -url $_) {
            $insecureHttpUrls += [PSObject]@{ type = "web"; url = $_; }
        }
    }
    
    # Check for expired credentials
    $now = Get-Date
    $expiredCreds = $app.PasswordCredential | Where-Object { $_.EndDateTime -lt $now }
    $expiredCerts = $app.KeyCredential | Where-Object { $_.EndDateTime -lt $now }
    
    # Check OAuth2 Code flow without PKCE
    $pkceRisk = $app.IsFallbackPublicClient -and $app.web.redirectUris.Count -gt 0
    
    # Skip apps which don't have abusable URLs
    if ($appAbusableReplyURLs.Count -eq 0) {
        continue
    }
    
    Write-Host "[RISK] App Display Name: $($app.displayName), AppId: $($app.Appid)"
    Write-Host " Abusable reply URL"
    foreach ($appAbusableReplyURL in $appAbusableReplyURLs) {
        Write-Host " $($appAbusableReplyURL.url) ($($appAbusableReplyURL.type))"
    }
    
    # Report insecure HTTP URLs
    if ($insecureHttpUrls.Count -gt 0) {
        Write-Host " Insecure HTTP URLs:"
        foreach ($httpUrl in $insecureHttpUrls) {
            Write-Host " $($httpUrl.url) ($($httpUrl.type))"
        }
    }
    
    # Report expired credentials
    if ($expiredCreds.Count -gt 0) {
        Write-Host " [RISK] App has $($expiredCreds.Count) expired password credential(s)"
    }
    
    if ($expiredCerts.Count -gt 0) {
        Write-Host " [RISK] App has $($expiredCerts.Count) expired certificate credential(s)"
    }
    
    # Report PKCE risk
    if ($pkceRisk) {
        Write-Host " [RISK] App uses Authorization Code flow without PKCE enforcement"
    }
    
    Write-Host ""
    
    # Write App Permissions (Permission Analysis)
    getOAuthResourceName -resources $app.RequiredResourceAccess
    Write-Host ""
    
    # Add to results for CSV export
    $riskDetails = @{
        AppDisplayName = $app.DisplayName
        AppId = $app.AppId
        ObjectId = $app.Id
        CreatedDateTime = $app.CreatedDateTime
        AbusableURLs = ($appAbusableReplyURLs | ForEach-Object { "$($_.url) ($($_.type))" }) -join "; "
        InsecureHttpUrls = ($insecureHttpUrls | ForEach-Object { "$($_.url) ($($_.type))" }) -join "; "
        ExpiredCredentials = $expiredCreds.Count
        ExpiredCertificates = $expiredCerts.Count
        PKCERisk = $pkceRisk
        Permissions = ($app.RequiredResourceAccess | ForEach-Object { $_.ResourceAppId }) -join "; "
    }
    $results += New-Object PSObject -Property $riskDetails
}

# Complete progress tracking
Write-Progress -Activity "Checking Entra ID Apps" -Completed

# Summary statistics
Write-Host "`n========== SUMMARY =========="
Write-Host "Total apps scanned: $($apps.Count)"
Write-Host "Apps with risky redirect URLs: $($results.Count)"
$appsWithoutRedirects = ($apps | Where-Object { 
    [string]::IsNullOrEmpty($_.Spa.RedirectUri) -and 
    [string]::IsNullOrEmpty($_.PublicClient.RedirectUri) -and 
    [string]::IsNullOrEmpty($_.Web.RedirectUri) 
}).Count
Write-Host "Apps with no redirect URLs: $appsWithoutRedirects"

# Export results to CSV
if ($results.Count -gt 0) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $filename = "EntraID_RiskyApps_$timestamp.csv"
    $results | Export-Csv -Path $filename -NoTypeInformation
    Write-Host "`nResults exported to: $filename"
} else {
    Write-Host "`nNo risky apps found - no CSV file created."
}