param([string]$Ids)
$u = "https://export.arxiv.org/api/query?id_list=$Ids&max_results=20"
for($i=0;$i -lt 3;$i++){ try{ $r = Invoke-WebRequest -Uri $u -TimeoutSec 45 -UseBasicParsing; break }catch{ Start-Sleep -Seconds 3 } }
[xml]$x = $r.Content
$ns = New-Object System.Xml.XmlNamespaceManager($x.NameTable); $ns.AddNamespace("a","http://www.w3.org/2005/Atom")
foreach($e in $x.SelectNodes("//a:entry",$ns)){
  $s = ($e.summary -replace '\s+',' ').Trim(); if($s.Length -gt 900){$s=$s.Substring(0,900)+'...'}
  Write-Output ("== " + ($e.id -replace '.*abs/','') + " | " + (($e.title -replace '\s+',' ').Trim()))
  Write-Output "   $s"; Write-Output ""
}
