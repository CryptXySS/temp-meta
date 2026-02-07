$all=@()

$rdp=Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 3000 | ForEach-Object{
 $e=$_ 
 if($e.Properties.Count -gt 8 -and $e.Properties[8].Value -eq 10){
  if($e.Properties.Count -gt 18){$src=$e.Properties[18].Value}else{$src=''}
  [PSCustomObject]@{
   TimeStamp=$e.TimeCreated
   Protocol='RDP'
   User=("{0}\{1}" -f ($e.Properties[5].Value),($e.Properties[6].Value)).Trim('\')
   SourceIP=$src
   Detail=($e.Message -replace "\r?\n"," ")
  }
 }
}
$all+=$rdp

$ssh=Get-WinEvent -LogName "OpenSSH/Operational" -MaxEvents 3000 -ErrorAction SilentlyContinue | Where-Object{
 $_.Message -match 'Accepted (password|publickey).*for'
} | ForEach-Object{
 $m=($_.Message -replace "\r?\n"," ")
 if($m -match 'Accepted (?:password|publickey) for (\S+) from (\d{1,3}(?:\.\d{1,3}){3})'){
  [PSCustomObject]@{
   TimeStamp=$_.TimeCreated
   Protocol='SSH'
   User=$matches[1]
   SourceIP=$matches[2]
   Detail=$m
  }
 }
}
$all+=$ssh

$log="$env:ProgramData\ssh\logs\sftp-server.log"
if(Test-Path $log){
 $sftp=Get-Content $log -Tail 3000 | ForEach-Object{
  if($_ -match '(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*user\s+\'?([^\'\s]+)\'?.*from\s+(\d{1,3}(?:\.\d{1,3}){3})'){
   [PSCustomObject]@{
    TimeStamp=[datetime]$matches[1]
    Protocol='SFTP'
    User=$matches[2]
    SourceIP=$matches[3]
    Detail=$_
   }
  }
 }
 $all+=$sftp
}

$ftpLogs=Get-ChildItem "$env:SystemDrive\inetpub\logs\LogFiles" -Recurse -Include "FTPSVC*" -File -ErrorAction SilentlyContinue
foreach($f in $ftpLogs){
 $fieldsLine=(Select-String -Path $f.FullName -Pattern '^#Fields:' | Select-Object -First 1).Line
 if(!$fieldsLine){continue}
 $fields=($fieldsLine -replace '^#Fields:\s*','').Split(' ')
 Select-String -Path $f.FullName -Pattern '^[^#]' | ForEach-Object{
  $cols=$_.Line.Split(' ')
  $o=[PSCustomObject]@{}
  for($i=0;$i -lt $fields.Count;$i++){ $o | Add-Member -NotePropertyName $fields[$i] -NotePropertyValue $cols[$i] }
  if($o.'cs-username'){
   $all+=[PSCustomObject]@{
    TimeStamp=[datetime]::ParseExact("$($o.date) $($o.time)","yyyy-MM-dd HH:mm:ss",$null)
    Protocol='FTP'
    User=$o.'cs-username'
    SourceIP=$o.'c-ip'
    Detail="$($o.'cs-method') $($o.'cs-uri-stem')"
   }
  }
 }
}

$all | Sort-Object TimeStamp -Descending | Format-Table -AutoSize
