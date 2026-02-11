param(
    [Parameter(Mandatory = $true)]
    [string]$Ip,
    [int]$Port = 8080
)

$ErrorActionPreference = "Stop"

$Base = "http://$Ip`:$Port"

function Section($title) {
    Write-Host ""
    Write-Host $title
}

Section "GET /"
curl.exe -sS "$Base/"

Section "GET /static/"
curl.exe -sS "$Base/static/"
$staticHeaders = curl.exe -sS -D - "$Base/static/" -o NUL
$etag = ($staticHeaders | Select-String -Pattern "^ETag:" | ForEach-Object { $_.Line.Substring(5).Trim() } | Select-Object -First 1)
$cache = ($staticHeaders | Select-String -Pattern "^Cache-Control:" | ForEach-Object { $_.Line.Substring(14).Trim() } | Select-Object -First 1)
if ($cache) {
    Write-Host "Cache-Control: $cache"
}
if ($etag) {
    Section "GET /static/ (If-None-Match)"
    curl.exe -sS -i -H "If-None-Match: $etag" "$Base/static/"
}

Section "GET /static/large.txt (Accept-Encoding: gzip)"
$gzipHeaders = curl.exe -sS -D - -H "Accept-Encoding: gzip" "$Base/static/large.txt" -o NUL
$encoding = ($gzipHeaders | Select-String -Pattern "^Content-Encoding:" | ForEach-Object { $_.Line.Substring(17).Trim() } | Select-Object -First 1)
if ($encoding) {
    Write-Host "Content-Encoding: $encoding"
}

Section "GET /static/large.txt"
$largeHeaders = curl.exe -sS -D - "$Base/static/large.txt" -o NUL
$etagLarge = ($largeHeaders | Select-String -Pattern "^ETag:" | ForEach-Object { $_.Line.Substring(5).Trim() } | Select-Object -First 1)
if ($etagLarge) {
    Write-Host "ETag (large): $etagLarge"
    Section "GET /static/large.txt (If-None-Match)"
    curl.exe -sS -i -H "If-None-Match: $etagLarge" "$Base/static/large.txt"
}

Section "GET /static/large.txt (Range bytes=0-63)"
curl.exe -sS -i -H "Accept-Encoding: identity" -H "Range: bytes=0-63" "$Base/static/large.txt"

if ($etagLarge) {
    Section "GET /static/large.txt (If-Range ETag)"
    curl.exe -sS -i -H "Accept-Encoding: identity" -H "Range: bytes=0-63" -H "If-Range: $etagLarge" "$Base/static/large.txt"
}
$lmLarge = ($largeHeaders | Select-String -Pattern "^Last-Modified:" | ForEach-Object { $_.Line.Substring(14).Trim() } | Select-Object -First 1)
if ($lmLarge) {
    Section "GET /static/large.txt (If-Range Last-Modified)"
    curl.exe -sS -i -H "Accept-Encoding: identity" -H "Range: bytes=0-63" -H "If-Range: $lmLarge" "$Base/static/large.txt"
}

Section "GET /static/large.txt (Range invalid)"
curl.exe -sS -i -H "Accept-Encoding: identity" -H "Range: bytes=999999999-" "$Base/static/large.txt"

Section "GET /static/large.txt (Range multi, expect 416)"
curl.exe -sS -i -H "Accept-Encoding: identity" -H "Range: bytes=0-3,8-15" "$Base/static/large.txt"

Section "GET /hello"
curl.exe -sS "$Base/hello"

Section "GET /redirect (no follow, expect 307 + Location)"
curl.exe -sS -i --max-redirs 0 "$Base/redirect"

Section "GET /items/7"
curl.exe -sS "$Base/items/7"

Section "GET /query?q=abc&page=2"
curl.exe -sS "$Base/query?q=abc&page=2"

Section "GET /query-typed?q=abc&page=2&ratio=1.5&active=true"
curl.exe -sS "$Base/query-typed?q=abc&page=2&ratio=1.5&active=true"

Section "GET /template"
curl.exe -sS "$Base/template?name=Ana&show_items=true&items=alpha,%3Cb%3E"

Section "GET /openapi.json"
$openapi = curl.exe -sS "$Base/openapi.json"
if ($openapi) {
    $preview = if ($openapi.Length -gt 320) { $openapi.Substring(0, 320) + "..." } else { $openapi }
    Write-Host $preview
}

Section "GET /docs"
$docsHeaders = curl.exe -sS -D - "$Base/docs" -o NUL
$docsType = ($docsHeaders | Select-String -Pattern "^Content-Type:" | ForEach-Object { $_.Line.Substring(13).Trim() } | Select-Object -First 1)
if ($docsType) {
    Write-Host "Content-Type: $docsType"
}

Section "GET /deps"
curl.exe -sS "$Base/deps"

Section "GET /api/ping"
curl.exe -sS "$Base/api/ping"

Section "POST /json (valid)"
'{"x":1}' | curl.exe -sS -X POST -H "Content-Type: application/json" --data-binary '@-' "$Base/json"

Section "POST /json (invalid, expect 400)"
'{' | curl.exe -sS -i -X POST -H "Content-Type: application/json" --data-binary '@-' "$Base/json"

Section "POST /request-info"
curl.exe -sS -X POST -H "X-Test: 123" -H "Content-Type: text/plain" -d "hello" "$Base/request-info?foo=bar"

Section "POST /uploadfile"
$tmpUpload = Join-Path $env:TEMP "vhttp-upload-note.txt"
Set-Content -Path $tmpUpload -Value "filedata" -NoNewline
curl.exe -sS -X POST -F "title=hello" -F "file=@$tmpUpload;type=text/plain;filename=note.txt" "$Base/uploadfile"
Remove-Item $tmpUpload -Force -ErrorAction SilentlyContinue

Section "GET /file"
$fileHeaders = curl.exe -sS -D - "$Base/file" -o NUL
$fileEtag = ($fileHeaders | Select-String -Pattern "^ETag:" | ForEach-Object { $_.Line.Substring(5).Trim() } | Select-Object -First 1)
$fileLm = ($fileHeaders | Select-String -Pattern "^Last-Modified:" | ForEach-Object { $_.Line.Substring(14).Trim() } | Select-Object -First 1)

Section "GET /file (Range bytes=0-63)"
curl.exe -sS -i -H "Range: bytes=0-63" "$Base/file"

if ($fileEtag) {
    Section "GET /file (If-Range ETag)"
    curl.exe -sS -i -H "Range: bytes=0-63" -H "If-Range: $fileEtag" "$Base/file"
}
if ($fileLm) {
    Section "GET /file (If-Range Last-Modified)"
    curl.exe -sS -i -H "Range: bytes=0-63" -H "If-Range: $fileLm" "$Base/file"
}

Section "GET /file (Range invalid)"
curl.exe -sS -i -H "Range: bytes=999999999-" "$Base/file"

Section "GET /file (Range multi, expect 416)"
curl.exe -sS -i -H "Range: bytes=0-3,8-15" "$Base/file"
