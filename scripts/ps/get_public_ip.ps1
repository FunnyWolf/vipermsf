$WebRequest = [System.Net.WebRequest]::Create("https://ipwho.is")
$WebRequest.Method = "GET"
$WebRequest.ContentType = "application/json"
$Response = $WebRequest.GetResponse()
$ResponseStream = $Response.GetResponseStream()
$ReadStream = New-Object System.IO.StreamReader $ResponseStream
$Data = $ReadStream.ReadToEnd()
Write-Host $Data