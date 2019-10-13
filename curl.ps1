[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;

$DATABASEDOTCOM_CLIENT_ID="3MVG9pe2TCoA1Pf6b.MWGLscN_7l51xXAF79OFZmjqfNPto3JohTujho1eWZErHffpBnRYVH8889zpruvUOp0"
$DATABASEDOTCOM_CLIENT_SECRET="D57E4EBC49CB0CACF946BAECD60514F3284FB917215C88667F79A679949B4D77"
$DATABASEDOTCOM_CLIENT_USERNAME="mushimaruko%40gmail.com"
$DATABASEDOTCOM_CLIENT_AUTHENTICATE_PASSWORD="#42Mushi3"
$DATABASEDOTCOM_HOST="login.salesforce.com"
$h = @{grant_type="password";
    clident_id=$DATABASEDOTCOM_CLIENT_ID;
    client_secret=$DATABASEDOTCOM_CLIENT_SECRET;
    username=$DATABASEDOTCOM_CLIENT_USERNAME;
    password=$DATABASEDOTCOM_CLIENT_AUTHENTICATE_PASSWORD}
try{
Invoke-WebRequest -Uri  https://$DATABASEDOTCOM_HOST/services/oauth2/token -Method Post  -Body $h
}
catch {
    echo '### Inside catch ###'
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    $result = $_.Exception.Response.GetResponseStream()
    echo '## result2 ##' $result
   $reader = New-Object System.IO.StreamReader($result)
    echo '## reader ##' $reader 
   $responseBody = $reader.ReadToEnd();
    echo '## responseBody ##' $responseBody
   
}
