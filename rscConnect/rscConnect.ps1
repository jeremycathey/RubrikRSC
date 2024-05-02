######Beginning of rscConnect Function
function rscConnect() {
  [CmdletBinding(DefaultParameterSetName = 'ServiceAccountFile')]
  param (
      [Parameter(ParameterSetName = 'ServiceAccountFile')]
      [String]$ServiceAccountPath,
      [Parameter(ParameterSetName = 'AccessToken')]
      [String]$AccessToken
  )

  Write-Information -Message "Info: Attempting to read the Service Account file located at $($ServiceAccountPath)"
  try {
      switch ($PSCmdlet.ParameterSetName) {
          'ServiceAccountFile' {
              $serviceAccountFile = Get-Content -Path $ServiceAccountPath -ErrorAction Stop | ConvertFrom-Json
              $payload = @{
                  grant_type = "client_credentials";
                  client_id = $serviceAccountFile.client_id;
                  client_secret = $serviceAccountFile.client_secret
              }   
          
              Write-Debug -Message "Determing if the Service Account file contains all required variables."
              $missingServiceAccount = @()
              if ($null -eq $serviceAccountFile.client_id) {
                  $missingServiceAccount += "'client_id'"
              }
          
              if ($null -eq $serviceAccountFile.client_secret) {
                  $missingServiceAccount += "'client_secret'"
              }
          
              if ($null -eq $serviceAccountFile.access_token_uri) {
                  $missingServiceAccount += "'access_token_uri'"
              }
          
          
              if ($missingServiceAccount.count -gt 0){
                  throw "The Service Account JSON secret file is missing the required paramaters: $missingServiceAccount"
              }

              $headers = @{
                  'Content-Type' = 'application/json';
                  'Accept'       = 'application/json';
              }

              Write-Debug -Message "Connecting to the Polaris GraphQL API using the Service Account JSON file."
              $response = Invoke-RestMethod -Method POST -Uri $serviceAccountFile.access_token_uri -Body $($payload | ConvertTo-JSON -Depth 100) -Headers $headers
              $AccessToken = "Bearer " + $response.access_token
              $rscURL  = $serviceAccountFile.access_token_uri.Replace("/api/client_token", "/api/graphql")
          }
          'AccessToken' {
              $rscURL = getUrlFromJwt -jwt $AccessToken.split(" ")[1]
          }
          Default {}
      }
      
  }
  catch {      
      throw $_.Exception
  }
  
  Write-Verbose -Message "Creating the Rubrik Polaris Connection Global variable."
  $global:rscConnection = @{
      access_token      = $AccessToken
      rscURL        = $rscURL
  }
  Write-Output "Connected!"
}
######End of rscConnect Function

##############################################Must change path to path of your RSC Service Account JSON File##############################################

#Call rscConnect to get Service Account Contents & Get Access Token
rscConnect -ServiceAccountPath ~/.rubrik/gaia-service-account-file.json

##############################################Must change path to path of your RSC Service Account JSON File##############################################