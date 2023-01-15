param(
    [string] $slackWebhook
)

$vulnerabilities = @();

docker build -t scan-me-console-app ./ConsoleApp
docker build -t scan-me-spa ./my-app

#Scan the file system
$fileSystemJson = docker run --rm `
    -v ${pwd}/trivytmp:/root/.cache `
    -v /var/run/docker.sock:/var/run/docker.sock `
    -v ${pwd}/:/scan-me `
    aquasec/trivy `
    fs `
    --format json `
    --security-checks vuln `
    --severity HIGH,CRITICAL `
    scan-me

#Scan the Console App Docker Image
$consoleDockerJson = docker run --rm `
    -v ${pwd}/trivytmp:/root/.cache `
    -v /var/run/docker.sock:/var/run/docker.sock `
    aquasec/trivy `
    image `
    --format json `
    --security-checks vuln `
    --severity HIGH,CRITICAL `
    scan-me-console-app;

#Scan the Angular SPA on Nginx Docker Image
$spaDockerJson = docker run --rm `
    -v ${pwd}/trivytmp:/root/.cache `
    -v /var/run/docker.sock:/var/run/docker.sock `
    aquasec/trivy `
    image `
    --format json `
    --security-checks vuln `
    --severity HIGH,CRITICAL `
    scan-me-spa;

$jsonToScan = @( $spaDockerJson, $consoleDockerJson, $fileSystemJson );

$jsonToScan | ForEach-Object {
    $_ | ConvertFrom-Json | ForEach-Object {
        $findings = $_;
        $findings.Results | Where-Object { $_.type -ne "dotnet-core" } | ForEach-Object {            
            $result = $_;            
            $_.Vulnerabilities | ForEach-Object {
                $vulnerability = $_;
                if($null -ne $vulnerability){
                    $vulnerabilities += [pscustomobject]@{
                        type = $result.type
                        name = $vulnerability.pkgName
                        version = $vulnerability.installedVersion
                        severity = $vulnerability.severity
                        cve = $vulnerability.vulnerabilityID
                        url = $vulnerability.primaryURL
                    };
                }                
            }                       
        };
    }    
}


if($null -ne $slackWebhook){

    $formattedVulnerabilities = "";

    $vulnerabilities | Group-Object -Property type | ForEach-Object {
        $type = $_.Name;

        if($type -eq "debian" -or $type -eq "alpine"){
            $type = ":penguin: ${type}";
        }
        if($type -eq "npm" -or $type -eq "yarn" -or $type -eq "nuget") {
            $type = ":package: ${type}";
        }

        if($_.Count -gt 0) {
            $formattedVulnerabilities += "*$type*`n";
            
            $_.Group | Sort-Object -Property severity -Descending | ForEach-Object {            
                $name = $_.name;
                $version = $_.version;
                $severity = $_.severity;
                $cve = $_.cve;
                $url = $_.url;

                if($severity -eq "critical"){
                    $severity = ":fire: ${severity}";
                }            

                $severity = $severity.ToLower();

                $formattedVulnerabilities += "- *$severity* - $name[$version] has the cve <$url|$cve>`n"
            }
        }
    }

    $body = [pscustomobject]@{
        text = $formattedVulnerabilities
    };

    $bodyJson = $body | ConvertTo-Json;
    
    Invoke-WebRequest -Uri "$slackWebhook" `
        -Method Post `
        -Body $bodyJson `
        -ContentType "application/json";
}
else{
    Write-Host $vulnerabilities
}