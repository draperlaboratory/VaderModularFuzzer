# Check in admin role
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output "Installing dependencies for whole system"
} else {
    Write-Output "This script must be run from an administrator powershell"
    exit -1
}

# Install Chocolatey
Set-ExecutionPolicy Bypass -Scope Process -Force; 
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; 
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Verify installation
choco -? | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to install chocolatey"
    exit -1
} else {
    Write-Host "Successfully installed chocolatey"
}

# Install Visual Studio with C++ build support
choco install --yes curl getopt git

# Get Draper Certificates
curl https://network-public.pages.draper.com/sslbundle/ca-certificates.crt -o ca-certificates.crt; 
curl https://network-public.pages.draper.com/sslbundle/draper_root.crt -o draper_root.crt; 
curl https://network-public.pages.draper.com/sslbundle/draper_issue.crt -o draper_issue.crt;

# Trust Draper Certificates
Import-Certificate C:\draper_root.crt -CertStoreLocation Cert:\LocalMachine\Root;
Import-Certificate C:\draper_issue.crt -CertStoreLocation Cert:\LocalMachine\Root;
Import-Certificate C:\ca-certificates.crt -CertStoreLocation Cert:\LocalMachine\Root;


choco install --yes visualstudio2022community --package-parameters "--locale en-US --add Microsoft.VisualStudio.Component.VC.TestAdapterForGoogleTest"
choco install --yes visualstudio2022-workload-nativedesktop 