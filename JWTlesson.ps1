$HeaderString='{
  "alg" : "RS256"
  
}'
$HeaderByte = ([System.Text.Encoding]::Default).GetBytes($HeaderString)
$HeaderBase64 = $([convert]::ToBase64String($HeaderByte))
$exptime = [int][double]::parse((Get-Date -Date $((Get-Date).addseconds($ValidforSeconds).ToUniversalTime()) -UFormat %s)) + 280
$LoginMap = @{
  iss="3MVG9pe2TCoA1Pf6b.MWGLscN_7l51xXAF79OFZmjqfNPto3JohTujho1eWZErHffpBnRYVH8889zpruvUOp0";
  aud='https://login.salesforce.com';
  sub='mushimaruko@gmail.com';
  exp=$exptime;
};
$LoginJson = $($LoginMap | ConvertTo-Json)
$LoginByte = $(([System.Text.Encoding]::Default).GetBytes($LoginJson) )
$LoginBase64 = $([convert]::ToBase64String($LoginByte))

$JWTRequest = $HeaderBase64 + "." + $LoginBase64
$arg = New-Object System.Security.Cryptography.HMACSHA256
$arg.Key = [System.Text.Encoding]::UTF8.GetBytes('.\server.key')
$Signature = [Convert]::ToBase64String($arg.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($JWTRequest))).Split('=')[0].Replace('+', '-').Replace('/', '_')
$jwt = $JWTRequest + '.' + $Signature
$b = @{grant_type='urn:ietf:params:oauth:grant-type:jwt-bearer';
    assertion=$jwt
}
$EndPoint = 'https://login.salesforce.com/services/oauth2/token'
Invoke-WebRequest -Uri $EndPoint -Method Post -Body $b

#$key = $(cat .\server.key)