# These components will be loaded when running Microsoft.Powershell

Push-Location (Join-Path (Split-Path -parent $profile) "components")

# From within the ./components directory...
. .\console.ps1

Pop-Location
