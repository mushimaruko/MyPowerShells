function aaa (){[System.Net.ServicePointManager]::SecurityProtocol =  [System.Net.ServicePointManager]::SecurityProtocol +  [System.Net.SecurityProtocolType]::Tls12;
#定数定義
#SSL Key File
$SSLKeyFile = "C:\Users\mushi\.PowerShell\MyPowerShells\server.key"
$SFDCFixedGrantCode = "urn:ietf:params:oauth:grant-type:jwt-bearer"
$SFDCKey="3MVG9pe2TCoA1Pf6b.MWGLscN_7l51xXAF79OFZmjqfNPto3JohTujho1eWZErHffpBnRYVH8889zpruvUOp0"
$SFDCLoginURL = "https://login.salesforce.com"
$SFDCLoginUser = "mushimaruko@gmail.com"
$SFDCEndPoint =  "https://login.salesforce.com/services/oauth2/token"
$HeaderString='{"alg" : "RH256"}'
$ValidforSeconds = 250
#固定文言のJsonヘッダー情報をBASE64へ変換する。
$HeaderByte = $([System.Text.Encoding]::Default).GetBytes($HeaderString)
$HeaderBase64 = $([System.Convert]::ToBase64String($HeaderByte))
#Tokenの有効時間を算出し、Unix時間へ変換する。
$NowTimeAddSec = $((Get-Date).AddSeconds($ValidforSeconds).ToUniversalTime() )
$exptime = [int][double]::parse((Get-Date $NowTimeAddSec -UFormat %s)) 
#Login用のJWTを構築し、Base64Formatへ変換する。
$LoginMap = @{
  iss=$SFDCKey;
  aud=$SFDCLoginURL;
  sub=$SFDCLoginUser;
  exp=$exptime;
};
$LoginJson = $($LoginMap | ConvertTo-Json)
$LoginByte = $(([System.Text.Encoding]::Default).GetBytes($LoginJson) )
$LoginBase64 = $([System.Convert]::ToBase64String($LoginByte))
#JWTの本文を構築する。
$JWTRequest = $HeaderBase64 + "." + $LoginBase64
#証明書による、サイン情報の構築
$arg = New-Object System.Security.Cryptography.HMACSHA256
$arg.Key = $([System.Text.Encoding]::Default.GetBytes(($(Get-Content $SSLKeyFile))))
$Signature = $([System.Convert]::ToBase64String($arg.ComputeHash([System.Text.Encoding]::Default.GetBytes($JWTRequest))))
#SFDC用PostMessageの構築
$jwt = $JWTRequest + '.' + $Signature
$FullMessage = @{grant_type=$SFDCFixedGrantCode;
    assertion=$jwt
}
$EndPoint = $SFDCEndPoint
#Curl実行
try {Invoke-WebRequest -Uri $EndPoint -Method Post -Body $FullMessage}
catch [System.Net.WebException] {
  echo '### Inside catch ###'
  $ErrorMessage = $_.Exception.Message
  $FailedItem = $_.Exception.ItemName
#  $result = New-Object System.IO.Stream
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
