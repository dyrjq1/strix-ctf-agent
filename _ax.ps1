param([string]$Q,[int]$N=8)
$u = "https://export.arxiv.org/api/query?search_query=" + [uri]::EscapeDataString($Q) + "&start=0&max_results=$N&sortBy=relevance"
for($i=0;$i -lt 3;$i++){
  try{ $r = Invoke-WebRequest -Uri $u -TimeoutSec 45 -UseBasicParsing; break }catch{ Start-Sleep -Seconds 3 }
}
[xml]$x = $r.Content
$ns = New-Object System.Xml.XmlNamespaceManager($x.NameTable)
$ns.AddNamespace("a","http://www.w3.org/2005/Atom")
foreach($e in $x.SelectNodes("//a:entry",$ns)){
  $id = $e.id -replace '.*abs/',''
  $t = ($e.title -replace '\s+',' ').Trim()
  $s = ($e.summary -replace '\s+',' ').Trim()
  if($s.Length -gt 700){$s = $s.Substring(0,700)+'...'}
  Write-Output "== $id | $t"
  Write-Output "   $s"
  Write-Output ""
}
