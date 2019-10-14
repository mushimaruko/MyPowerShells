$headerString='{
  "alg" : "HS256",
  "typ" : "JWT"
}'
$headerByte = ([System.Text.Encoding]::Default).GetBytes($headerString)
$headerBase64 = $([convert]::ToBase64String($headerByte))

$LoginMap = @{
  iss="3MVG9pe2TCoA1Pf6b.MWGLscN_7l51xXAF79OFZmjqfNPto3JohTujho1eWZErHffpBnRYVH8889zpruvUOp0";
  aud='https://login.salesforce.com';
  sub='mushimaruko@gmail.com';
  exp='1571029200';
};
$LoginJson = $($LoginMap | ConvertTo-Json)
$LoginByte = $(([System.Text.Encoding]::Default).GetBytes($LoginJson) )
$LoginBase64 = $([convert]::ToBase64String($LoginByte))

$key = $(cat .\server.key)