# Check to see if we are currently running "as Administrator"
if (!(Verify-Elevated)) {
   $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";
   $newProcess.Arguments = $myInvocation.MyCommand.Definition;
   $newProcess.Verb = "runas";
   [System.Diagnostics.Process]::Start($newProcess);

   exit
}


### Update Help for Modules
Write-Host "Updating Help..." -ForegroundColor "Yellow"
Update-Help -Force


### Install PowerShell Modules
Write-Host "Installing PowerShell Modules..." -ForegroundColor "Yellow"
Install-Module Posh-Git -Scope CurrentUser -Force
Install-Module PSWindowsUpdate -Scope CurrentUser -Force


### Chocolatey
Write-Host "Installing Desktop Utilities..." -ForegroundColor "Yellow"
if ((which cinst) -eq $null) {
    Invoke-Expression (new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1')
    Refresh-Environment
    choco feature enable -n=allowGlobalConfirmation
}

# system and cli
choco install curl                  --limit-output
choco install nano                  --limit-output
choco install wget                  --limit-output
choco install git.install           --limit-output -params '"/GitAndUnixToolsOnPath /NoShellIntegration"'
choco install ruby                  --limit-output

# utilities
choco install 7zip                  --limit-output
choco install notepadplusplus       --limit-output
choco install mobaxterm             --limit-output
choco install vlc                   --limit-output
choco install spotify               --limit-output
choco install f.lux                 --limit-output
choco install screentogif           --limit-output

# java dev
choco install javaruntime           --limit-output
choco install jdk8                  --limit-output
choco install maven                 --limit-output
choco install gradle                --limit-output
choco install intellijidea-ultimate --limit-output
choco install kotlinc               --limit-output

# node dev
choco install nodejs                --limit-output
choco install yarn                  --limit-output

$info = "Which environment are you on?"
$options = [System.Management.Automation.Host.ChoiceDescription[]] @("&Home", "&Work")
[int]$defaultchoice = 1
$opt = $host.UI.PromptForChoice("" , $Info , $Options,$defaultchoice)
switch($opt)
{
    0 {
        # home specific packages
        choco install steam                        --limit-output
        choco install libreoffice                  --limit-output
     }
    1 {
        # work specific packages
        choco install sql-server-management-studio --limit-output
        choco install firefox                      --limit-output
        choco install kubernetes-cli               --limit-output
        choco install nvda                         --limit-output
     }
}

Refresh-Environment

gem pristine --all --env-shebang

### Node Packages
Write-Host "Installing Node Packages..." -ForegroundColor "Yellow"
if (which npm) {
    npm update npm
    npm install -g typescript
    npm install -g grunt-cli
    npm install -g yo
}


### Visual Studio Code Plugins
if (which code) {
    ### Visual Studio 2015
    # VsVim
    # Install-VSExtension https://visualstudiogallery.msdn.microsoft.com/59ca71b3-a4a3-46ca-8fe1-0e90e3f79329/file/6390/57/VsVim.vsix
    # Productivity Power Tools 2015
    # Install-VSExtension https://visualstudiogallery.msdn.microsoft.com/34ebc6a2-2777-421d-8914-e29c1dfa7f5d/file/169971/1/ProPowerTools.vsix

    ### Visual Studio 2013
    # VsVim
    # Install-VSExtension https://visualstudiogallery.msdn.microsoft.com/59ca71b3-a4a3-46ca-8fe1-0e90e3f79329/file/6390/57/VsVim.vsix
    # Productivity Power Tools 2013
    # Install-VSExtension https://visualstudiogallery.msdn.microsoft.com/dbcb8670-889e-4a54-a226-a48a15e4cace/file/117115/4/ProPowerTools.vsix
    # Web Essentials 2013
    # Install-VSExtension https://visualstudiogallery.msdn.microsoft.com/56633663-6799-41d7-9df7-0f2a504ca361/file/105627/47/WebEssentials2013.vsix
}
