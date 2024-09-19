# Request Admin Privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {   
    Start-Process -FilePath 'powershell' -ArgumentList ('-File', $MyInvocation.MyCommand.Source, $args ` | %{ $_ }) -Verb RunAs
    exit
}

# Function to add exclusion
function Add-WDExclusion {
    param (
        [string]$Path
    )

    # Validate the path
    if ($null -eq $Path) {
        Write-Host "No path provided. Please run the script with a path argument."
        exit
    }

    if (!(Test-Path $Path)) {
        Write-Host "The specified path does not exist."
        exit
    }

    try {
        # Get current preferences
        $preferences = Get-MpPreference

        # Check if the path is already excluded
        if ($preferences.ExclusionPath -contains $Path) {
            Write-Host "The path '$Path' is already excluded."
            return
        }

        # Add the new exclusion
        $preferences.ExclusionPath += $Path
        Set-MpPreference -ExclusionPath $preferences.ExclusionPath

        Write-Host "Successfully added '$Path' to Windows Defender exclusions."
    }
    catch {
        Write-Host "An error occurred while adding the exclusion: $_"
    }
}

Add-WDExclusion -Path $args[0]
