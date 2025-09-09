

# Entra ID Apps Redirect URL Security Scanner

This PowerShell script scans Azure AD (Entra ID) applications for security vulnerabilities in redirect URLs that could lead to tenant takeover attacks.

It performs comprehensive checks including DNS resolution validation, insecure protocol detection, risky network address identification, application configuration risks, and permission analysis.

## Security Validations

The script performs the following security checks:

### 1. DNS Resolution Validation
- **Unresolvable Domains**: Identifies redirect URLs pointing to domains that don't resolve via DNS
- **Purpose**: Attackers can register expired/unregistered domains to hijack authentication flows

### 2. Insecure Protocol Detection
- **HTTP vs HTTPS**: Flags redirect URLs using insecure HTTP protocol
- **Purpose**: HTTP URLs are vulnerable to man-in-the-middle attacks and credential interception

### 3. Risky Network Addresses
- **Localhost/Loopback**: Detects localhost, 127.0.0.1, ::1 addresses
- **Private IP Ranges**: Identifies private network addresses (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
- **Wildcard Domains**: Flags domains containing wildcard characters (*)
- **Purpose**: These addresses can be controlled by attackers or represent overly permissive configurations

### 4. Application Configuration Risks
- **Expired Credentials**: Identifies apps with expired passwords or certificates
- **PKCE Enforcement**: Detects OAuth2 Authorization Code flow without PKCE protection
- **Implicit Grant Flow**: Flags web applications with implicit grant enabled (higher risk)
- **Purpose**: Misconfigurations that weaken security posture

### 5. Permission Analysis
- **OAuth2 Scopes**: Lists all permissions requested by risky applications
- **Resource Access**: Shows which Microsoft services the app can access
- **Purpose**: Helps assess potential impact if application is compromised

## Output

The script generates:
- **Console Output**: Real-time analysis with risk indicators
- **CSV Export**: Detailed report with timestamps for compliance/audit purposes
- **Summary Statistics**: Overview of total apps scanned and risks found

## Usage

```powershell
# Authenticate to Azure (uncomment if needed)
# Connect-AzAccount -AuthScope MicrosoftGraphEndpointResourceId

# Run the security scan
.\ListEntraIdAppsMissingDNSv2.ps1
```

## Requirements

- Azure PowerShell module (Az.Resources, Az.Accounts)
- Appropriate Azure AD permissions to read application registrations
- PowerShell 5.1 or later

## Reference

https://falconforce.nl/arbitrary-1-click-azure-tenant-takeover-via-ms-application/