function aaa (){[System.Net.ServicePointManager]::SecurityProtocol =  [System.Net.ServicePointManager]::SecurityProtocol +  [System.Net.SecurityProtocolType]::Tls12;
$HeaderString='{
  "alg" : "RH256"
  
}'
$HeaderByte = ([System.Text.Encoding]::Default).GetBytes($HeaderString)
$HeaderBase64 = $([convert]::ToBase64String($HeaderByte))
$ValidforSeconds = 250
$exptime = [int][double]::parse((Get-Date -Date $((Get-Date).addseconds($ValidforSeconds).ToUniversalTime()) -UFormat %s)) 
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
$arg.Key = [System.Text.Encoding]::Default.GetBytes(($(Get-Content '.\server.key')))
$Signature = [Convert]::ToBase64String($arg.ComputeHash([System.Text.Encoding]::Default.GetBytes($JWTRequest)))
$jwt = $JWTRequest + '.' + $Signature
$b = @{grant_type='urn:ietf:params:oauth:grant-type:jwt-bearer';
    assertion=$jwt
}
$EndPoint = 'https://login.salesforce.com/services/oauth2/token'
try {Invoke-WebRequest -Uri $EndPoint -Method Post -Body $b}catch{
  echo '### Inside catch ###'
  $ErrorMessage = $_.Exception.Message
  $FailedItem = $_.Exception.ItemName
  $result = $_.Exception.Response.GetResponseStream()
  Write-Output '## result2 ##' $result
 $reader = New-Object System.IO.StreamReader($result)
 Write-Output '## reader ##' $reader 
 $responseBody = $reader.ReadToEnd();
 Write-Output '## responseBody ##' $responseBody
 Write-Output $ErrorMessage
 Write-Output $FailedItem
}
}
