param(
    [string]$Username = "alice",
    [string]$Password = "alice-pass"
)

$body = @{
    client_id     = "sil-api"
    client_secret = "demo-secret-change-me"
    grant_type    = "password"
    username      = $Username
    password      = $Password
}

try {
    $response = Invoke-RestMethod -Uri "http://localhost:8080/realms/savannah/protocol/openid-connect/token" -Method Post -Body $body
    Write-Output $response.access_token
} catch {
    Write-Error "Failed to obtain token for $Username : $_"
    exit 1
}
