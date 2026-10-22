param(
    [ValidateSet('curl','webrequest','httpclient')]
    [string]$Engine='curl',
    [ValidateSet('any','ipv4','ipv6')]
    [string]$Family='any',
    [ValidateRange(2,20)]
    [int]$TimeoutSeconds=10,
    [string]$ObservationPath
)

$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$uri='https://www.cloudflare.com/cdn-cgi/trace'
$result=[ordered]@{ Engine=$Engine; Family=$Family; Success=$false; Seconds=$null; EgressIP=$null; TLS=$null; RemoteIP=$null; ErrorType=$null; ErrorChain=@(); CurlExitCode=$null }
if ($ObservationPath) {
    if ((Split-Path ([IO.Path]::GetFullPath($ObservationPath)) -Parent) -ne $PSScriptRoot -or
        (Split-Path $ObservationPath -Leaf) -notmatch '^probe-\d+\.json$' -or (Test-Path -LiteralPath $ObservationPath)) {
        throw 'Use a new probe metadata file beside the protected probe script.'
    }
    [IO.File]::WriteAllText($ObservationPath,(@{ ProcessId=$PID } | ConvertTo-Json -Compress))
}
$watch=[Diagnostics.Stopwatch]::StartNew()
try {
    if ($Engine -eq 'curl') {
        $selection=@()
        if ($Family -eq 'ipv4') { $selection=@('-4') }
        if ($Family -eq 'ipv6') { $selection=@('-6') }
        $ErrorActionPreference='Continue'
        $lines=@(& curl.exe --noproxy '*' @selection --fail --silent --show-error --connect-timeout ([Math]::Min(4,$TimeoutSeconds)) --max-time $TimeoutSeconds --write-out "`nF4G_METRICS %{remote_ip}" $uri 2>$null)
        $exitCode=$LASTEXITCODE
        $result.CurlExitCode=$exitCode
        $ErrorActionPreference='Stop'
        if ($exitCode -ne 0) { throw "curl_exit_$exitCode" }
        $body=$lines -join "`n"
        $metadata=@($lines | Where-Object { $_ -like 'F4G_METRICS *' })
        if ($metadata.Count) { $result.RemoteIP=($metadata[-1] -split ' ')[1] }
    } elseif ($Family -ne 'any') {
        throw 'Explicit family selection is supported only for curl.'
    } else {
        [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
        if ($Engine -eq 'webrequest') {
            [Net.WebRequest]::DefaultWebProxy=$null
            $body=[string](Invoke-WebRequest -UseBasicParsing -TimeoutSec $TimeoutSeconds -Uri $uri).Content
        } else {
            Add-Type -AssemblyName System.Net.Http
            $handler=[Net.Http.HttpClientHandler]::new()
            $handler.UseProxy=$false
            $client=[Net.Http.HttpClient]::new($handler)
            $client.Timeout=[TimeSpan]::FromSeconds($TimeoutSeconds)
            try { $body=$client.GetStringAsync($uri).GetAwaiter().GetResult() }
            finally { $client.Dispose(); $handler.Dispose() }
        }
    }
    $values=@{}
    foreach ($line in ($body -split "`n")) {
        if ($line -match '^([^=]+)=(.*)$') { $values[$matches[1]]=$matches[2].Trim() }
    }
    $address=$null
    if (-not [Net.IPAddress]::TryParse($values.ip,[ref]$address) -or -not $values.tls.StartsWith('TLS')) {
        throw 'Invalid certificate-verified HTTPS trace.'
    }
    $result.EgressIP=$address.ToString()
    $result.TLS=$values.tls
    $result.Success=$true
} catch {
    $result.ErrorType=$_.Exception.GetType().FullName
    $exception=$_.Exception
    for ($index=0; $index -lt 5 -and $null -ne $exception; $index++) {
        $detail=@{ Type=$exception.GetType().FullName }
        if ($exception -is [Net.WebException]) { $detail.Status=$exception.Status.ToString() }
        $result.ErrorChain+=@($detail)
        $exception=$exception.InnerException
    }
} finally {
    $watch.Stop()
    $result.Seconds=[Math]::Round($watch.Elapsed.TotalSeconds,3)
}
$result | ConvertTo-Json -Compress
exit 0
