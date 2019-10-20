[System.Net.ServicePointManager]::SecurityProtocol =  [System.Net.ServicePointManager]::SecurityProtocol +  [System.Net.SecurityProtocolType]::Tls12;
$SSLKeyFile = "C:\Users\mushi\.PowerShell\MyPowerShells\server.key"
$SFDCFixedGrantCode = "urn:ietf:params:oauth:grant-type:jwt-bearer"
$SFDCKey="3MVG9pe2TCoA1Pf6b.MWGLscN_7l51xXAF79OFZmjqfNPto3JohTujho1eWZErHffpBnRYVH8889zpruvUOp0"
$SFDCLoginURL = "https://login.salesforce.com"
$SFDCLoginUser = "mushimaruko@gmail.com"
$SFDCEndPoint =  "https://login.salesforce.com/services/oauth2/token"
$HeaderString='{"alg" : "RH256"}'
$ValidforSeconds = 250
function aaa (){
    #定数定義
    #SSL Key File
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
    #$reader = New-Object System.IO.StreamReader($result)
    Write-Output '## reader ##' $reader 
    $responseBody = $reader.ReadToEnd();
    Write-Output '## responseBody ##' $responseBody
    Write-Output $ErrorMessage
    Write-Output $FailedItem
    }
}

function New-Jwt {
    <#
    .SYNOPSIS
    Creates a JWT (JSON Web Token).
     
    .DESCRIPTION
    Creates signed JWT given a signing certificate and claims in JSON.
     
    .PARAMETER Payload
    Specifies the claim to sign in JSON. Mandatory.
     
    .PARAMETER Cert
    Specifies the signing certificate. Mandatory.
     
    .PARAMETER Header
    Specifies a JWT header. Optional. Defaults to '{"alg":"RS256","typ":"JWT"}'.
     
    .INPUTS
    You can pipe a string object (the JSON payload) to New-Jwt.
     
    .OUTPUTS
    System.String. New-Jwt returns a string with the signed JWT.
     
    .EXAMPLE
    PS Variable:\> $cert = (Get-ChildItem Cert:\CurrentUser\My)[1]
     
    PS Variable:\> New-Jwt -Cert $cert -PayloadJson '{"token1":"value1","token2":"value2"}'
    eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbjEiOiJ2YWx1ZTEiLCJ0b2tlbjIiOiJ2YWx1ZTIifQ.Kd12ryF7Uuk9Y1UWsqdSk6cXNoYZBf9GBoqcEz7R5e4ve1Kyo0WmSr-q4XEjabcbaG0hHJyNGhLDMq6BaIm-hu8ehKgDkvLXPCh15j9AzabQB4vuvSXSWV3MQO7v4Ysm7_sGJQjrmpiwRoufFePcurc94anLNk0GNkTWwG59wY4rHaaHnMXx192KnJojwMR8mK-0_Q6TJ3bK8lTrQqqavnCW9vrKoWoXkqZD_4Qhv2T6vZF7sPkUrgsytgY21xABQuyFrrNLOI1g-EdBa7n1vIyeopM4n6_Uk-ttZp-U9wpi1cgg2pRIWYV5ZT0AwZwy0QyPPx8zjh7EVRpgAKXDAg
     
    .EXAMPLE
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("/mnt/c/PS/JWT/jwt.pfx","jwt")
     
    $now = (Get-Date).ToUniversalTime()
    $createDate = [Math]::Floor([decimal](Get-Date($now) -UFormat "%s"))
    $expiryDate = [Math]::Floor([decimal](Get-Date($now.AddHours(1)) -UFormat "%s"))
    $rawclaims = [Ordered]@{
        iss = "examplecom:apikey:uaqCinPt2Enb"
        iat = $createDate
        exp = $expiryDate
    } | ConvertTo-Json
     
    $jwt = New-Jwt -PayloadJson $rawclaims -Cert $cert
     
    $apiendpoint = "https://api.example.com/api/1.0/systems"
     
    $splat = @{
        Method="GET"
        Uri=$apiendpoint
        ContentType="application/json"
        Headers = @{authorization="bearer $jwt"}
    }
     
    Invoke-WebRequest @splat
     
    .LINK
    https://github.com/SP3269/posh-jwt
    .LINK
    https://jwt.io/
     
    #>
    
    
        [CmdletBinding()]
        param (
        #    [Parameter(Mandatory=$false)][string]$Header = '{"alg":"RS256","typ":"JWT"}',
        #    [Parameter(Mandatory=$true,ValueFromPipeline=$true)][string]$PayloadJson,
        #    [Parameter(Mandatory=$true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert
        )
        [string]$Header = '{"alg":"RS256","typ":"JWT"}'
        $LoginMap = @{
            iss=$SFDCKey;
            aud=$SFDCLoginURL;
            sub=$SFDCLoginUser;
            exp=$exptime;
            };
        $Ceart = $SSLKeyFile
        [string]$PayloadJson = $($LoginMap | ConvertTo-Json)
        Write-Verbose "Payload to sign: $PayloadJson"
        Write-Verbose "Signing certificate: $($Cert.Subject)"
    
        try { ConvertFrom-Json -InputObject $payloadJson -ErrorAction Stop | Out-Null } # Validating that the parameter is actually JSON - if not, generate breaking error
        catch { throw "The supplied JWT payload is not JSON: $payloadJson" }
    
        $encodedHeader = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Header)) -replace '\+','-' -replace '/','_' -replace '='
        $encodedPayload = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($PayloadJson)) -replace '\+','-' -replace '/','_' -replace '='
    
        $jwt = $encodedHeader + '.' + $encodedPayload # The first part of the JWT
    
        $toSign = [System.Text.Encoding]::UTF8.GetBytes($jwt)
        
        $rsa = $Cert.PrivateKey
        if ($null -eq $rsa) { # Requiring the private key to be present; else cannot sign!
            throw "There's no private key in the supplied certificate - cannot sign" 
        }
        else {
            # Overloads tested with RSACryptoServiceProvider, RSACng, RSAOpenSsl
            try { $sig = [Convert]::ToBase64String($rsa.SignData($toSign,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)) -replace '\+','-' -replace '/','_' -replace '=' }
            catch { throw "Signing with SHA256 and Pkcs1 padding failed using private key $rsa" }
        }
    
        $jwt = $jwt + '.' + $sig
    
        return $jwt
    
    }
    
    
    function Test-Jwt {
    <#
    .SYNOPSIS
    Tests cryptographic integrity of a JWT (JSON Web Token).
     
    .DESCRIPTION
    Verifies a digital signature of a JWT given a signing certificate. Assumes SHA-256 hashing algorithm. Optionally produces the original signed JSON payload.
     
    .PARAMETER Payload
    Specifies the JWT. Mandatory string.
     
    .PARAMETER Cert
    Specifies the signing certificate. Mandatory X509Certificate2.
     
    .INPUTS
    You can pipe JWT as a string object to Test-Jwt.
     
    .OUTPUTS
    Boolean. Test-Jwt returns $true if the signature successfully verifies.
     
    .EXAMPLE
     
    PS Variable:> $jwt | Test-Jwt -cert $cert -Verbose
    VERBOSE: Verifying JWT: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbjEiOiJ2YWx1ZTEiLCJ0b2tlbjIiOiJ2YWx1ZTIifQ.Kd12ryF7Uuk9Y1UWsqdSk6cXNoYZBf9GBoqcEz7R5e4ve1Kyo0WmSr-q4XEjabcbaG0hHJyNGhLDMq6BaIm-hu8ehKgDkvLXP
    Ch15j9AzabQB4vuvSXSWV3MQO7v4Ysm7_sGJQjrmpiwRoufFePcurc94anLNk0GNkTWwG59wY4rHaaHnMXx192KnJojwMR8mK-0_Q6TJ3bK8lTrQqqavnCW9vrKoWoXkqZD_4Qhv2T6vZF7sPkUrgsytgY21xABQuyFrrNLOI1g-EdBa7n1vIyeopM4n6_Uk-ttZp-U9wpi1cgg2p
    RIWYV5ZT0AwZwy0QyPPx8zjh7EVRpgAKXDAg
    VERBOSE: Using certificate with subject: CN=jwt_signing_test
    True
     
    .LINK
    https://github.com/SP3269/posh-jwt
    .LINK
    https://jwt.io/
     
    #>
    
    
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=$true,ValueFromPipeline=$true)][string]$jwt,
            [Parameter(Mandatory=$true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert
        )
    
        Write-Verbose "Verifying JWT: $jwt"
        Write-Verbose "Using certificate with subject: $($Cert.Subject)"
    
        $parts = $jwt.Split('.')
    
        if ($OutputJSON) {
            $OutputJSON.value = [Convert]::FromBase64String($parts[1].replace('-','+').replace('_','/'))
        }
    
        $SHA256 = New-Object Security.Cryptography.SHA256Managed
        $computed = $SHA256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($parts[0]+"."+$parts[1])) # Computing SHA-256 hash of the JWT parts 1 and 2 - header and payload
        
        $signed = $parts[2].replace('-','+').replace('_','/') # Decoding Base64url to the original byte array
        $mod = $signed.Length % 4
        switch ($mod) {
            0 { $signed = $signed }
            1 { $signed = $signed.Substring(0,$signed.Length-1) }
            2 { $signed = $signed + "==" }
            3 { $signed = $signed + "=" }
        }
        $bytes = [Convert]::FromBase64String($signed) # Conversion completed
    
        return $cert.PublicKey.Key.VerifyHash($computed,$bytes,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1) # Returns True if the hash verifies successfully
    
    }
    
    New-Alias -Name "Verify-JwtSignature" -Value "Test-Jwt" -Description "An alias, using non-standard verb"
    
    function Get-JwtPayload {
        <#
        .SYNOPSIS
        Gets JSON payload from a JWT (JSON Web Token).
         
        .DESCRIPTION
        Decodes and extracts JSON payload from JWT. Ignores headers and signature.
         
        .PARAMETER Payload
        Specifies the JWT. Mandatory string.
         
        .INPUTS
        You can pipe JWT as a string object to Get-JwtPayload.
         
        .OUTPUTS
        String. Get-JwtPayload returns $true if the signature successfully verifies.
         
        .EXAMPLE
         
        PS Variable:> $jwt | Get-JwtPayload -Verbose
        VERBOSE: Processing JWT: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbjEiOiJ2YWx1ZTEiLCJ0b2tlbjIiOiJ2YWx1ZTIifQ.Kd12ryF7Uuk9Y1UWsqdSk6cXNoYZBf9GBoqcEz7R5e4ve1Kyo0WmSr-q4XEjabcbaG0hHJyNGhLDMq6BaIm-hu8ehKgDkvLXPCh15j9AzabQB4vuvSXSWV3MQO7v4Ysm7_sGJQjrmpiwRoufFePcurc94anLNk0GNkTWwG59wY4rHaaHnMXx192KnJojwMR8mK-0_Q6TJ3bK8lTrQqqavnCW9vrKoWoXkqZD_4Qhv2T6vZF7sPkUrgsytgY21xABQuyFrrNLOI1g-EdBa7n1vIyeopM4n6_Uk-ttZp-U9wpi1cgg2pRIWYV5ZT0AwZwy0QyPPx8zjh7EVRpgAKXDAg
        {"token1":"value1","token2":"value2"}
         
        .LINK
        https://github.com/SP3269/posh-jwt
        .LINK
        https://jwt.io/
         
        #>
        
        
            [CmdletBinding()]
            param (
                [Parameter(Mandatory=$true,ValueFromPipeline=$true)][string]$jwt
            )
        
            Write-Verbose "Processing JWT: $jwt"
                
            $parts = $jwt.Split('.')
        
            $payload = $parts[1].replace('-','+').replace('_','/') # Decoding Base64url to the original byte array
            $mod = $payload.Length % 4
            switch ($mod) {
                # 0 { $payload = $payload } - do nothing
                1 { $payload = $payload.Substring(0,$payload.Length-1) }
                2 { $payload = $payload + "==" }
                3 { $payload = $payload + "=" }
            }
            $bytes = [Convert]::FromBase64String($payload) # Conversion completed
    
            return [System.Text.Encoding]::UTF8.GetString($bytes)
        
        }