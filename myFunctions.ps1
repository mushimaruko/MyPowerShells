#cat のUTF8化
#
#
function cat8($strFname){
    Get-Content $strFname -Encoding UTF8
}
#UTF8Tree取得
function mTree ( $strFileName ){
    $ExportFileName
    if ($strFileName){
        $ExportFileName = $strFileName
    } else{
        $ExportFileName = 'aaa.csv'
    }
    Get-ChildItem ./ -Recurse| Where-Object { $_ -is [system.io.fileinfo]} | Select-Object name , fullname | Export-Csv $ExportFileName -Encoding UTF8
    Write-Host "Tree List is created which name is :" $ExportFileName
}
#grep 
#
#
function grep ($P_searchString, $P_findPath, $P_excludeKeyWord){
    if (!($P_searchString)){
        Write-Host "Please input search string."
        Write-host "Exit Function"
        return;
    }else{
        $serchString = $P_searchString
    }
    if ($P_findPath){
        $findPath =$P_findPath
    }else{
        $findPath ="*.*"
    }

    if($P_excludeKeyWord){
        $excludeKeyWord = $P_excludeKeyWord
    }else{
        $excludeKeyWord = "*TEST*"
    }
    
    
    Select-String $serchString $findPath -Exclude $excludeKeyWord -Encoding utf8 

}

