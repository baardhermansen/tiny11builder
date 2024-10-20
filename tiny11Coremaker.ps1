# Enable debugging
#Set-PSDebug -Trace 1

# Check if PowerShell execution is restricted
if ((Get-ExecutionPolicy) -eq 'Restricted') {
    Write-Host "Your current PowerShell Execution Policy is set to Restricted, which prevents scripts from running."
    $response = Read-Host "Do you want to change it to RemoteSigned? (yes/no)"
    if ($response -in 'yes', 'y') {
        Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Confirm:$false
    }
    else {
        Write-Host "The script cannot be run without changing the execution policy. Exiting..."
        exit
    }
}

# Check and run the script as admin if required
$adminSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
$adminGroup = $adminSID.Translate([System.Security.Principal.NTAccount])
$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
if (! $myWindowsPrincipal.IsInRole($adminRole)) {
    Write-Host "Restarting Tiny11 image creator as admin in a new window, you can close this one."
    $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";
    $newProcess.Arguments = $myInvocation.MyCommand.Definition;
    $newProcess.Verb = "runas";
    [System.Diagnostics.Process]::Start($newProcess);
    exit
}

# Welcome message
Write-Host "Welcome to tiny11 core builder! BETA 05-06-24"
Write-Host "This script generates a significantly reduced Windows 11 image."
Write-Host "However, it's not suitable for regular use due to its lack of serviceability - you can't add languages, updates, or features post-creation."
Write-Host "tiny11 Core is not a full Windows 11 substitute but a rapid testing or development tool, potentially useful for VM environments.`n"

# Ensure user wants to continue, if not exit
$inputContinue = Read-Host -Prompt "Do you want to continue? (y/n)"
if ($inputContinue -ne 'y') {
    Write-Host "You didn't enter 'y'. The script will now exit."
    exit
}

Clear-Host
Start-Transcript -Path "$PSScriptRoot\tiny11.log"

# Set variables
$mainOSDrive = $env:SystemDrive
$scratchDir = "$mainOSDrive\scratchdir"
$tinyFolder = "$mainOSDrive\tiny11"
$hostArchitecture = $Env:PROCESSOR_ARCHITECTURE

# Get DVD drive(s), since mounted ISOs show as CD-ROM
$potentialDLs = Get-Volume | Where-Object { ($PSItem.DriveType -eq "CD-ROM") -and ($Null -ne $PSItem.DriveLetter) } | Sort-Object DriveLetter
if ($potentialDLs) {
    "Found one or more CD-ROM drives with a Windows image in them."
    "Drive letter - Volume label"
    foreach ($potentialDL in $potentialDLs) {
        "$($potentialDL.DriveLetter): - '$($potentialDL.FileSystemLabel)'"
    }
    $driveLetter = Read-Host -Prompt "Type the correct drive letter"
}
else {
    $driveLetter = Read-Host "Please enter the drive letter for the mounted Windows iso"
}

# Making sure drive letter is in correct format
$driveLetter = $driveLetter.Substring(0, 1) + ":"

# Create the tiny11 folder
New-Item -ItemType Directory -Force -Path $tinyFolder | Out-Null

# Test if wim files exist, if not, convert esd to wim
if ((Test-Path "$driveLetter\sources\boot.wim") -eq $false -or (Test-Path "$driveLetter\sources\install.wim") -eq $false) {
    if ((Test-Path "$driveLetter\sources\install.esd") -eq $true) {
        New-Item -ItemType Directory -Force -Path "$tinyFolder\sources" | Out-Null
        Write-Host "Found install.esd file."
        &  'dism' '/English' "/Get-WimInfo" "/wimfile:$driveLetter\sources\install.esd"
        $index = Read-Host "Please enter the image index"
        Write-Host ' '
        Write-Host 'Converting install.esd to install.wim. This may take a while...'
        & 'DISM' /Export-Image /SourceImageFile:"$driveLetter\sources\install.esd" /SourceIndex:$index /DestinationImageFile:"$tinyFolder\sources\install.wim" /Compress:max /CheckIntegrity
    }
    else {
        Write-Host "Can't find Windows OS Installation files in the specified Drive Letter."
        Write-Host "Please enter the correct DVD Drive Letter."
        exit
    }
}

Write-Host "Copying Windows image..."
Copy-Item -Path "$driveLetter\*" -Destination $tinyFolder -Recurse -Force | Out-Null
Set-ItemProperty -Path "$tinyFolder\sources\install.esd" -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue
Remove-Item "$tinyFolder\sources\install.esd" -ErrorAction SilentlyContinue
$wimFilePath = "$tinyFolder\sources\install.wim"
Write-Host "Copy complete!"
Start-Sleep -Seconds 2
Clear-Host
Write-Host "Getting image information:"
&  'dism' '/English' "/Get-WimInfo" "/wimfile:$wimFilePath"
$index = Read-Host "Please enter the image index"
Write-Host "Mounting Windows image. This may take a while."
& takeown "/F" $wimFilePath
& icacls $wimFilePath "/grant" "$($adminGroup.Value):(F)"
try {
    Set-ItemProperty -Path $wimFilePath -Name IsReadOnly -Value $false -ErrorAction Stop
}
catch {
    # This block will catch the error and suppress it.
}
New-Item -ItemType Directory -Force -Path $scratchDir | Out-Null
& dism /English "/mount-image" "/imagefile:$wimFilePath" "/index:$index" "/mountdir:$scratchDir"

$imageIntl = & dism /English /Get-Intl "/Image:$scratchDir"
$languageLine = $imageIntl -split '\n' | Where-Object { $_ -match 'Default system UI language : ([a-zA-Z]{2}-[a-zA-Z]{2})' }

if ($languageLine) {
    $languageCode = $Matches[1]
    Write-Host "Default system UI language code: $languageCode"
}
else {
    Write-Host "Default system UI language code not found."
}

$imageInfo = & 'dism' '/English' '/Get-WimInfo' "/wimFile:$wimFilePath" "/index:$index"
$lines = $imageInfo -split '\r?\n'

foreach ($line in $lines) {
    if ($line -like '*Architecture : *') {
        $architecture = $line -replace 'Architecture : ', ''
        # If the architecture is x64, replace it with amd64
        if ($architecture -eq 'x64') {
            $architecture = 'amd64'
        }
        Write-Host "Architecture: $architecture"
        break
    }
}

if (-not $architecture) {
    Write-Host "Architecture information not found."
}

Write-Host "Mounting complete! Performing removal of applications..."

$packages = & 'dism' '/English' "/image:$scratchDir" '/Get-ProvisionedAppxPackages' |
ForEach-Object {
    if ($_ -match 'PackageName : (.*)') {
        $matches[1]
    }
}
$packagePrefixes = @(
    'Clipchamp.Clipchamp_',
    'Microsoft.SecHealthUI_',
    'Microsoft.Windows.PeopleExperienceHost_',
    'Microsoft.Windows.PinningConfirmationDialog_',
    'Windows.CBSPreview_',
    'Microsoft.BingNews_',
    'Microsoft.BingWeather_',
    'Microsoft.GamingApp_',
    'Microsoft.GetHelp_',
    'Microsoft.Getstarted_',
    'Microsoft.MicrosoftOfficeHub_',
    'Microsoft.MicrosoftSolitaireCollection_',
    'Microsoft.People_',
    'Microsoft.PowerAutomateDesktop_',
    'Microsoft.Todos_',
    'Microsoft.WindowsAlarms_',
    'microsoft.windowscommunicationsapps_',
    'Microsoft.WindowsFeedbackHub_',
    'Microsoft.WindowsMaps_',
    'Microsoft.WindowsSoundRecorder_',
    'Microsoft.Xbox.TCUI_',
    'Microsoft.XboxGamingOverlay_',
    'Microsoft.XboxGameOverlay_',
    'Microsoft.XboxSpeechToTextOverlay_',
    'Microsoft.YourPhone_',
    'Microsoft.ZuneMusic_',
    'Microsoft.ZuneVideo_',
    'MicrosoftCorporationII.MicrosoftFamily_',
    'MicrosoftCorporationII.QuickAssist_',
    'MicrosoftTeams_',
    'Microsoft.549981C3F5F10_'
)

$packagesToRemove = $packages | Where-Object {
    $packageName = $_
    $packagePrefixes -contains ($packagePrefixes | Where-Object { $packageName -like "$_*" })
}
foreach ($package in $packagesToRemove) {
    Write-Host "`nRemoving '$package'..."
    & 'dism' '/English' "/image:$scratchDir" '/Remove-ProvisionedAppxPackage' "/PackageName:$package"
}

Write-Host "Removing of system apps complete! Now proceeding to removal of system packages..."
Start-Sleep -Seconds 2
Clear-Host

$packagePatterns = @(
    "Microsoft-Windows-InternetExplorer-Optional-Package~31bf3856ad364e35",
    "Microsoft-Windows-Kernel-LA57-FoD-Package~31bf3856ad364e35~amd64",
    "Microsoft-Windows-LanguageFeatures-Handwriting-$languageCode-Package~31bf3856ad364e35",
    "Microsoft-Windows-LanguageFeatures-OCR-$languageCode-Package~31bf3856ad364e35",
    "Microsoft-Windows-LanguageFeatures-Speech-$languageCode-Package~31bf3856ad364e35",
    "Microsoft-Windows-LanguageFeatures-TextToSpeech-$languageCode-Package~31bf3856ad364e35",
    "Microsoft-Windows-MediaPlayer-Package~31bf3856ad364e35",
    "Microsoft-Windows-Wallpaper-Content-Extended-FoD-Package~31bf3856ad364e35",
    "Windows-Defender-Client-Package~31bf3856ad364e35~",
    "Microsoft-Windows-WordPad-FoD-Package~",
    "Microsoft-Windows-TabletPCMath-Package~",
    "Microsoft-Windows-StepsRecorder-Package~"
)

# Get all packages
$allPackages = & dism /image:$scratchDir /Get-Packages /Format:Table
$allPackages = $allPackages -split "`n" | Select-Object -Skip 1

foreach ($packagePattern in $packagePatterns) {
    # Filter the packages to remove
    $packagesToRemove = $allPackages | Where-Object { $_ -like "$packagePattern*" }

    foreach ($package in $packagesToRemove) {
        # Extract the package identity
        $packageIdentity = ($package -split "\s+")[0]

        Write-Host "`nRemoving '$packageIdentity'..."
        & dism /image:$scratchDir /Remove-Package /PackageName:$packageIdentity 
    }
}

# Enable .NET 3.5, if the user wants to
# Loop until the user enters either 'y' or 'n'
do {
    "`n"
    $input35 = Read-Host -Prompt "Do you want to enable .NET 3.5? (y/n)"
    if ($input35 -eq 'y') {
        # If the user entered 'y', enable .NET 3.5 using DISM
        Write-Host "Enabling .NET 3.5..."
        & 'dism'  "/image:$scratchDir" '/enable-feature' '/featurename:NetFX3' '/All' "/source:$tinyFolder\sources\sxs" 
        Write-Host ".NET 3.5 has been enabled."
    }
    elseif ($input35 -eq 'n') {
        # If the user entered 'n', exit the loop
        Write-Host "You chose not to enable .NET 3.5. Continuing..."
        break
    }
    else {
        # If the user entered anything other than 'y' or 'n', show an error message and loop again
        Write-Host "Invalid input. Please enter 'y' to enable .NET 3.5 or 'n' to continue without enabling .NET 3.5.`n"
    }
} until ($input35 -in 'y', 'n')

Write-Host "Removing Edge:"
Remove-Item -Path "$scratchDir\Program Files (x86)\Microsoft\Edge" -Recurse -Force | Out-Null
Remove-Item -Path "$scratchDir\Program Files (x86)\Microsoft\EdgeUpdate" -Recurse -Force | Out-Null
Remove-Item -Path "$scratchDir\Program Files (x86)\Microsoft\EdgeCore" -Recurse -Force | Out-Null

if ($architecture) {
    $folderPath = Get-ChildItem -Path "$scratchDir\Windows\WinSxS" -Filter "${architecture}_microsoft-edge-webview_31bf3856ad364e35*" -Directory | Select-Object -ExpandProperty FullName
    if ($folderPath) {
        & 'takeown' '/f' $folderPath '/r' >null
        # Grant the current user full access to the folder
        & icacls $folderPath  "/grant" "${env:username}:(F)" '/T' '/C' >null
        Remove-Item -Path $folderPath -Recurse -Force -ErrorAction SilentlyContinue
    }
    else {
        Write-Host "Folder not found."
    }
}
else {
    Write-Host "Unknown architecture: $(if ($null -eq $architecture) {'<blank>'} else {$architecture})"
}


Write-host "Removing EdgeWebView, WinRE, and OneDriveSetup.exe:"
$baseFolder = "$scratchDir\Windows\System32"
"$baseFolder\Microsoft-Edge-Webview", "$baseFolder\Recovery", "$baseFolder\OneDriveSetup.exe" | ForEach-Object { 
    & 'takeown' '/f' $_ '/r' >null
    & 'icacls' $_ '/grant' "${env:username}:(F)" '/T' '/C' >null
    Remove-Item -Path $_ -Recurse -Force | Out-Null
}

Write-Host "Removal complete!"
Start-Sleep -Seconds 2
Clear-Host
Write-Host "Taking ownership of the WinSxS folder. This might take a while..."
& 'takeown' '/f' "$scratchDir\Windows\WinSxS" '/r' >null
& 'icacls' "$scratchDir\Windows\WinSxS" '/grant' "$($adminGroup.Value):(F)" '/T' '/C' >null
Write-host "Complete!"
Start-Sleep -Seconds 2
Clear-Host
Write-Host "Preparing..."

$sourceDirectory = "$scratchDir\Windows\WinSxS"
$destinationDirectory = Join-Path -Path $scratchDir -ChildPath "Windows\WinSxS_edit"
New-Item -Path $destinationDirectory -ItemType Directory

# Specify the list of files to copy
# Common files
$commonDirsToCopy = @(
    "Catalogs"
    "FileMaps"
    "Fusion"
    "InstallTemp"
    "Manifests"
    "x86_microsoft.vc80.crt_1fc8b3b9a1e18e3b_*"
    "x86_microsoft.vc90.crt_1fc8b3b9a1e18e3b_*"
    "x86_microsoft.windows.i..utomation.proxystub_6595b64144ccf1df_*"
    "x86_microsoft.windows.isolationautomation_6595b64144ccf1df_*"
    "x86_microsoft.windows.c..-controls.resources_6595b64144ccf1df_*"
    "${architecture}_microsoft.windows.c..-controls.resources_6595b64144ccf1df_*"
    "${architecture}_microsoft.vc80.crt_1fc8b3b9a1e18e3b_*"
    "${architecture}_microsoft.vc90.crt_1fc8b3b9a1e18e3b_*"
    "${architecture}_microsoft-windows-servicingstack_31bf3856ad364e35_*"
    "${architecture}_microsoft.windows.common-controls_6595b64144ccf1df_*"
    "${architecture}_microsoft.windows.gdiplus_6595b64144ccf1df_*"
    "${architecture}_microsoft.windows.i..utomation.proxystub_6595b64144ccf1df_*"
    "${architecture}_microsoft.windows.isolationautomation_6595b64144ccf1df_*"
    "${architecture}_microsoft-windows-servicingstack-inetsrv_31bf3856ad364e35_*"
    "${architecture}_microsoft-windows-servicingstack-msg_31bf3856ad364e35_*"
    "${architecture}_microsoft-windows-servicingstack-onecore_31bf3856ad364e35_*"
)

if ($architecture -eq "amd64") {
    $dirsToCopy = @(
        "x86_microsoft-windows-s..ngstack-onecorebase_31bf3856ad364e35_*"
        "x86_microsoft-windows-s..stack-termsrv-extra_31bf3856ad364e35_*"
        "x86_microsoft-windows-servicingstack_31bf3856ad364e35_*"
        "x86_microsoft-windows-servicingstack-inetsrv_*"
        "x86_microsoft-windows-servicingstack-onecore_*"
        "amd64_microsoft-windows-s..stack-inetsrv-extra_31bf3856ad364e35_*"
        "amd64_microsoft-windows-s..stack-msg.resources_31bf3856ad364e35_*"
        "amd64_microsoft-windows-s..stack-termsrv-extra_31bf3856ad364e35_*"        
    )
}
elseif ($architecture -eq "arm64") {
    # Specify the list of files to copy
    $dirsToCopy = @(
        "SettingsManifests"
        "Temp"
        "arm_microsoft.windows.c..-controls.resources_6595b64144ccf1df_*"
        "arm_microsoft.windows.common-controls_6595b64144ccf1df_*"
        "arm_microsoft.windows.gdiplus_6595b64144ccf1df_*"
        "arm_microsoft.windows.i..utomation.proxystub_6595b64144ccf1df_*"
        "arm_microsoft.windows.isolationautomation_6595b64144ccf1df_*"
        "arm64_microsoft-windows-servicing-adm_31bf3856ad364e35_*"
        "arm64_microsoft-windows-servicingcommon_31bf3856ad364e35_*"
        "arm64_microsoft-windows-servicing-onecore-uapi_31bf3856ad364e35_*"
    )
}

# Copy each directory
$dirsToCopy += $commonDirsToCopy
foreach ($dir in $dirsToCopy) {
    $sourceDirs = Get-ChildItem -Path $sourceDirectory -Filter $dir -Directory
    foreach ($sourceDir in $sourceDirs) {
        $destDir = Join-Path -Path $destinationDirectory -ChildPath $sourceDir.Name
        Write-Host "Copying $sourceDir.FullName to $destDir"
        Copy-Item -Path $sourceDir.FullName -Destination $destDir -Recurse -Force
    }
}  


Write-Host "Deleting WinSxS. This may take a while..."
Remove-Item -Path $scratchDir\Windows\WinSxS -Recurse -Force

Rename-Item -Path $scratchDir\Windows\WinSxS_edit -NewName $scratchDir\Windows\WinSxS
Write-Host "Complete!"

Write-Host "Loading registry..."
reg load HKLM\zCOMPONENTS $scratchDir\Windows\System32\config\COMPONENTS >null
reg load HKLM\zDEFAULT $scratchDir\Windows\System32\config\default >null
reg load HKLM\zNTUSER $scratchDir\Users\Default\ntuser.dat >null
reg load HKLM\zSOFTWARE $scratchDir\Windows\System32\config\SOFTWARE >null
reg load HKLM\zSYSTEM $scratchDir\Windows\System32\config\SYSTEM >null
Write-Host "Bypassing system requirements (on the system image):"
& 'reg' 'add' 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' '/v' 'SV1' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' '/v' 'SV2' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' '/v' 'SV1' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' '/v' 'SV2' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassCPUCheck' '/t' 'REG_DWORD' '/d' '1' '/f' >null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassRAMCheck' '/t' 'REG_DWORD' '/d' '1' '/f' >null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassSecureBootCheck' '/t' 'REG_DWORD' '/d' '1' '/f' >null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassStorageCheck' '/t' 'REG_DWORD' '/d' '1' '/f' >null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassTPMCheck' '/t' 'REG_DWORD' '/d' '1' '/f' >null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\MoSetup' '/v' 'AllowUpgradesWithUnsupportedTPMOrCPU' '/t' 'REG_DWORD' '/d' '1' '/f' >null
Write-Host "Disabling Sponsored Apps:"
& 'reg' 'add' 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'OemPreInstalledAppsEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'PreInstalledAppsEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SilentInstalledAppsEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' '/v' 'DisableWindowsConsumerFeatures' '/t' 'REG_DWORD' '/d' '1' '/f' >null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'ContentDeliveryAllowed' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start' '/v' 'ConfigureStartPins' '/t' 'REG_SZ' '/d' '{"pinnedList": [{}]}' '/f' >null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'ContentDeliveryAllowed' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'ContentDeliveryAllowed' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'FeatureManagementEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'OemPreInstalledAppsEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'PreInstalledAppsEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'PreInstalledAppsEverEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SilentInstalledAppsEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SoftLandingEnabled' '/t' 'REG_DWORD' '/d' '0' '/f'>null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SubscribedContentEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SubscribedContent-310093Enabled' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SubscribedContent-338388Enabled' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SubscribedContent-338389Enabled' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SubscribedContent-338393Enabled' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SubscribedContent-353694Enabled' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SubscribedContent-353696Enabled' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SubscribedContentEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SystemPaneSuggestionsEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\PushToInstall' '/v' 'DisablePushToInstall' '/t' 'REG_DWORD' '/d' '1' '/f' >null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\MRT' '/v' 'DontOfferThroughWUAU' '/t' 'REG_DWORD' '/d' '1' '/f' >null
& 'reg' 'delete' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions' '/f' >null
& 'reg' 'delete' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps' '/f' >null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' '/v' 'DisableConsumerAccountStateContent' '/t' 'REG_DWORD' '/d' '1' '/f' >null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' '/v' 'DisableCloudOptimizedContent' '/t' 'REG_DWORD' '/d' '1' '/f' >null
Write-Host "Enabling Local Accounts on OOBE:"
& 'reg' 'add' 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\OOBE' '/v' 'BypassNRO' '/t' 'REG_DWORD' '/d' '1' '/f' >null
Copy-Item -Path "$PSScriptRoot\autounattend.xml" -Destination "$scratchDir\Windows\System32\Sysprep\autounattend.xml" -Force >null
Write-Host "Disabling Reserved Storage:"
& 'reg' 'add' 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager' '/v' 'ShippedWithReserves' '/t' 'REG_DWORD' '/d' '0' '/f' >null
Write-Host "Disabling BitLocker Device Encryption"
& 'reg' 'add' 'HKLM\zSYSTEM\ControlSet001\Control\BitLocker' '/v' 'PreventDeviceEncryption' '/t' 'REG_DWORD' '/d' '1' '/f' >null
Write-Host "Disabling Chat icon:"
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Chat' '/v' 'ChatIcon' '/t' 'REG_DWORD' '/d' '3' '/f' >null
& 'reg' 'add' 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' '/v' 'TaskbarMn' '/t' 'REG_DWORD' '/d' '0' '/f' >null
Write-Host "Disabling Telemetry:"
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' '/v' 'Enabled' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Privacy' '/v' 'TailoredExperiencesWithDiagnosticDataEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy' '/v' 'HasAccepted' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Input\TIPC' '/v' 'Enabled' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization' '/v' 'RestrictImplicitInkCollection' '/t' 'REG_DWORD' '/d' '1' '/f' >null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization' '/v' 'RestrictImplicitTextCollection' '/t' 'REG_DWORD' '/d' '1' '/f' >null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization\TrainedDataStore' '/v' 'HarvestContacts' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Personalization\Settings' '/v' 'AcceptedPrivacyPolicy' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection' '/v' 'AllowTelemetry' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zSYSTEM\ControlSet001\Services\dmwappushservice' '/v' 'Start' '/t' 'REG_DWORD' '/d' '4' '/f' >null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Chat' '/v' 'ChatIcon' '/t' 'REG_DWORD' '/d' '3' '/f' >null
& 'reg' 'add' 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' '/v' 'TaskbarMn' '/t' 'REG_DWORD' '/d' '0' '/f' >null
Write-Host "Disabling OneDrive folder backup"
& 'reg' 'add' "HKLM\zSOFTWARE\Policies\Microsoft\Windows\OneDrive" '/v' 'DisableFileSyncNGSC' '/t' 'REG_DWORD' '/d' '1' '/f' >null
Write-Host "Removing Edge related registries"
reg delete "HKEY_LOCAL_MACHINE\zSOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge" /f >null
reg delete "HKEY_LOCAL_MACHINE\zSOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge Update" /f >null
Write-Host "Disabling bing in Start Menu:"
& 'reg' 'add' 'HKLM\zNTUSER\Software\Policies\Microsoft\Windows\Explorer' >null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Policies\Microsoft\Windows\Explorer' '/v' 'ShowRunAsDifferentUserInStart' '/t' 'REG_DWORD' '/d' '1' '/f' >null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Policies\Microsoft\Windows\Explorer' '/v' 'DisableSearchBoxSuggestions' '/t' 'REG_DWORD' '/d' '1' '/f' >null
## this function allows PowerShell to take ownership of the Scheduled Tasks registry key from TrustedInstaller. Based on Jose Espitia's script.
function Enable-Privilege {
    param(
        [ValidateSet(
            "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege",
            "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege",
            "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
            "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",
            "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege",
            "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege",
            "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege",
            "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege",
            "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege",
            "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
            "SeUndockPrivilege", "SeUnsolicitedInputPrivilege")]
        $Privilege,
        ## The process on which to adjust the privilege. Defaults to the current process.
        $ProcessId = $pid,
        ## Switch to disable the privilege, rather than enable it.
        [Switch] $Disable
    )
    $definition = @'
 using System;
 using System.Runtime.InteropServices;
  
 public class AdjPriv
 {
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
   ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
  
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
  [DllImport("advapi32.dll", SetLastError = true)]
  internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  internal struct TokPriv1Luid
  {
   public int Count;
   public long Luid;
   public int Attr;
  }
  
  internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
  internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
  internal const int TOKEN_QUERY = 0x00000008;
  internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
  public static bool EnablePrivilege(long processHandle, string privilege, bool disable)
  {
   bool retVal;
   TokPriv1Luid tp;
   IntPtr hproc = new IntPtr(processHandle);
   IntPtr htok = IntPtr.Zero;
   retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
   tp.Count = 1;
   tp.Luid = 0;
   if(disable)
   {
    tp.Attr = SE_PRIVILEGE_DISABLED;
   }
   else
   {
    tp.Attr = SE_PRIVILEGE_ENABLED;
   }
   retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
   retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
   return retVal;
  }
 }
'@

    $processHandle = (Get-Process -id $ProcessId).Handle
    $type = Add-Type $definition -PassThru
    $type[0]::EnablePrivilege($processHandle, $Privilege, $Disable)
}

Enable-Privilege SeTakeOwnershipPrivilege

$regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::TakeOwnership)
$regACL = $regKey.GetAccessControl()
$regACL.SetOwner($adminGroup)
$regKey.SetAccessControl($regACL)
$regKey.Close()
Write-Host "Owner changed to Administrators."
$regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
$regACL = $regKey.GetAccessControl()
$regRule = New-Object System.Security.AccessControl.RegistryAccessRule ($adminGroup, "FullControl", "ContainerInherit", "None", "Allow")
$regACL.SetAccessRule($regRule)
$regKey.SetAccessControl($regACL)
Write-Host "Permissions modified for Administrators group."
Write-Host "Registry key permissions successfully updated."
$regKey.Close()

Write-Host 'Deleting Application Compatibility Appraiser'
reg delete "HKEY_LOCAL_MACHINE\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0600DD45-FAF2-4131-A006-0B17509B9F78}" /f >null
Write-Host 'Deleting Customer Experience Improvement Program'
reg delete "HKEY_LOCAL_MACHINE\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{4738DE7A-BCC1-4E2D-B1B0-CADB044BFA81}" /f >null
reg delete "HKEY_LOCAL_MACHINE\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{6FAC31FA-4A85-4E64-BFD5-2154FF4594B3}" /f >null
reg delete "HKEY_LOCAL_MACHINE\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{FC931F16-B50A-472E-B061-B6F79A71EF59}" /f >null
Write-Host 'Deleting Program Data Updater'
reg delete "HKEY_LOCAL_MACHINE\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0671EB05-7D95-4153-A32B-1426B9FE61DB}" /f >null
Write-Host 'Deleting autochk proxy'
reg delete "HKEY_LOCAL_MACHINE\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{87BF85F4-2CE1-4160-96EA-52F554AA28A2}" /f >null
reg delete "HKEY_LOCAL_MACHINE\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{8A9C643C-3D74-4099-B6BD-9C6D170898B1}" /f >null
Write-Host 'Deleting QueueReporting'
reg delete "HKEY_LOCAL_MACHINE\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{E3176A65-4E44-4ED3-AA73-3283660ACB9C}" /f >null
Write-Host "Disabling Windows Update..."
& 'reg' 'add' "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" '/v' 'StopWUPostOOBE1' '/t' 'REG_SZ' '/d' 'net stop wuauserv' '/f' >null
& 'reg' 'add' "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" '/v' 'StopWUPostOOBE2' '/t' 'REG_SZ' '/d' 'sc stop wuauserv' '/f' >null
& 'reg' 'add' "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" '/v' 'StopWUPostOOBE3' '/t' 'REG_SZ' '/d' 'sc config wuauserv start= disabled' '/f' >null
& 'reg' 'add' "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" '/v' 'DisbaleWUPostOOBE1' '/t' 'REG_SZ' '/d' 'reg add HKLM\SYSTEM\CurrentControlSet\Services\wuauserv /v Start /t REG_DWORD /d 4 /f' '/f' >null
& 'reg' 'add' "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" '/v' 'DisbaleWUPostOOBE2' '/t' 'REG_SZ' '/d' 'reg add HKLM\SYSTEM\ControlSet001\Services\wuauserv /v Start /t REG_DWORD /d 4 /f' '/f' >null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' '/v' 'DoNotConnectToWindowsUpdateInternetLocations' '/t' 'REG_DWORD' '/d' '1' '/f' >null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' '/v' 'DisableWindowsUpdateAccess' '/t' 'REG_DWORD' '/d' '1' '/f' >null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' '/v' 'WUServer' '/t' 'REG_SZ' '/d' 'localhost' '/f' >null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' '/v' 'WUStatusServer' '/t' 'REG_SZ' '/d' 'localhost' '/f' >null 
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' '/v' 'UpdateServiceUrlAlternate' '/t' 'REG_SZ' '/d' 'localhost' '/f' >null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' '/v' 'UseWUServer' '/t' 'REG_DWORD' '/d' '1' '/f' >null
& 'reg' 'add' 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\OOBE' '/v' 'DisableOnline' '/t' 'REG_DWORD' '/d' '1' '/f' >null
& 'reg' 'add' 'HKLM\zSYSTEM\ControlSet001\Services\wuauserv' '/v' 'Start' '/t' 'REG_DWORD' '/d' '4' '/f' >null
function Disable-Privilege {
    param(
        [ValidateSet(
            "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege",
            "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege",
            "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
            "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",
            "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege",
            "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege",
            "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege",
            "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege",
            "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege",
            "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
            "SeUndockPrivilege", "SeUnsolicitedInputPrivilege")]
        $Privilege,
        ## The process on which to adjust the privilege. Defaults to the current process.
        $ProcessId = $pid,
        ## Switch to disable the privilege, rather than enable it.
        [Switch] $Disable
    )
    $definition = @'
 using System;
 using System.Runtime.InteropServices;
  
 public class AdjPriv
 {
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
   ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
  
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
  [DllImport("advapi32.dll", SetLastError = true)]
  internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  internal struct TokPriv1Luid
  {
   public int Count;
   public long Luid;
   public int Attr;
  }
  
  internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
  internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
  internal const int TOKEN_QUERY = 0x00000008;
  internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
  public static bool EnablePrivilege(long processHandle, string privilege, bool disable)
  {
   bool retVal;
   TokPriv1Luid tp;
   IntPtr hproc = new IntPtr(processHandle);
   IntPtr htok = IntPtr.Zero;
   retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
   tp.Count = 1;
   tp.Luid = 0;
   if(disable)
   {
    tp.Attr = SE_PRIVILEGE_DISABLED;
   }
   else
   {
    tp.Attr = SE_PRIVILEGE_ENABLED;
   }
   retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
   retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
   return retVal;
  }
 }
'@

    $processHandle = (Get-Process -id $ProcessId).Handle
    $type = Add-Type $definition -PassThru
    $type[0]::EnablePrivilege($processHandle, $Privilege, $Disable)
}

Disable-Privilege SeTakeOwnershipPrivilege -Disable
$everyone = New-Object System.Security.Principal.NTAccount('Everyone')
#$accessRule = New-Object System.Security.AccessControl.RegistryAccessRule($everyone, 'ReadKey', 'Allow')
$regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("zSYSTEM\ControlSet001\Services\wuauserv", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::TakeOwnership)
$regACL = $regKey.GetAccessControl()
$regACL.SetOwner($everyone)
$regKey.Close()
Write-Host "Owner changed to Everyone."
$regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("zSYSTEM\ControlSet001\Services\wuauserv", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
$regACL = $regKey.GetAccessControl()
$regRule = New-Object System.Security.AccessControl.RegistryAccessRule ($everyone, 'ReadKey', 'Allow')
$regACL.SetAccessRule($regRule)
$regKey.SetAccessControl($regACL)
Write-Host "Permissions modified for Everyone group."
Write-Host "Registry key permissions successfully updated."


Write-Host "All users have been granted read-only access to the registry key."
$regKey.Close()
& 'reg' 'delete' "HKEY_LOCAL_MACHINE\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{2540477E-E654-4302-AD44-383BBFFBFF16}" '/f'
& 'reg' 'delete' "HKEY_LOCAL_MACHINE\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{341B2255-6A6B-442A-AF5A-C610B7DBE12D}" '/f'
& 'reg' 'delete' "HKEY_LOCAL_MACHINE\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{476E8CFA-78E2-4C51-854E-538F8643B4FD}" '/f'
& 'reg' 'delete' "HKEY_LOCAL_MACHINE\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{764DDB74-CB08-4E0A-8580-B41F94F2C7BE}" '/f'
& 'reg' 'delete' "HKEY_LOCAL_MACHINE\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{817CCFDD-4DD0-4102-AC6E-3F5D3B789FB8}" '/f'
& 'reg' 'delete' "HKEY_LOCAL_MACHINE\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{99CEDA8C-A866-4787-BBD3-6F3C9F61DD5C}" '/f'
& 'reg' 'delete' "HKEY_LOCAL_MACHINE\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{9B3CDCDA-4197-490B-AA5C-C9F5F42A9D88}" '/f'
& 'reg' 'delete' "HKEY_LOCAL_MACHINE\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{9CBBFAAE-DB9F-48B4-BAC0-4CFF482A4E01}" '/f'
& 'reg' 'delete' "HKEY_LOCAL_MACHINE\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{A31197EC-EAEE-4837-8A9C-3A17D358B9EB}" '/f'
& 'reg' 'delete' "HKEY_LOCAL_MACHINE\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{B4FBEFA9-6F7C-4C74-A891-3774B7BCD072}" '/f'
& 'reg' 'delete' "HKEY_LOCAL_MACHINE\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{B53BD60A-5823-411C-9C75-AA91DB3C35F8}" '/f'
& 'reg' 'delete' "HKEY_LOCAL_MACHINE\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{CECDC345-7460-4A15-9D8B-DAC3F9CC5368}" '/f'
& 'reg' 'delete' "HKEY_LOCAL_MACHINE\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{E0F10DCF-44AD-40E8-9370-FB5DA59F93FB}" '/f'
& 'reg' 'delete' 'HKLM\zSYSTEM\ControlSet001\Services\WaaSMedicSVC' '/f'
& 'reg' 'delete' 'HKLM\zSYSTEM\ControlSet001\Services\UsoSvc' '/f'
& 'reg' 'add' 'HKEY_LOCAL_MACHINE\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' '/v' 'NoAutoUpdate' '/t' 'REG_DWORD' '/d' '1' '/f'
Write-Host "Disabling Windows Defender"
# Set registry values for Windows Defender services
$servicePaths = @(
    "WinDefend",
    "WdNisSvc",
    "WdNisDrv",
    "WdFilter",
    "Sense"
)

foreach ($path in $servicePaths) {
    Set-ItemProperty -Path "HKLM:\zSYSTEM\ControlSet001\Services\$path" -Name "Start" -Value 4
}
& 'reg' 'add' 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' '/v' 'SettingsPageVisibility' '/t' 'REG_SZ' '/d' 'hide:virus;windowsupdate' '/f' 
Write-Host "Tweaking complete!"
Write-Host "Unmounting Registry..."
$regKey.Close()
reg unload HKLM\zCOMPONENTS >null
reg unload HKLM\zDEFAULT >null
reg unload HKLM\zNTUSER >null
reg unload HKLM\zSOFTWARE
reg unload HKLM\zSYSTEM >null
Write-Host "Cleaning up image..."
& 'dism' '/English' "/image:$scratchDir" '/Cleanup-Image' '/StartComponentCleanup' '/ResetBase' >null
Write-Host "Cleanup complete."
Write-Host ' '
Write-Host "Unmounting image..."
& 'dism' '/English' '/unmount-image' "/mountdir:$scratchDir" '/commit'
Write-Host "Exporting image..."
& 'dism' '/English' '/Export-Image' "/SourceImageFile:$wimFilePath" "/SourceIndex:$index" "/DestinationImageFile:$tinyFolder\sources\install2.wim" '/compress:max'
Remove-Item -Path "$wimFilePath" -Force >null
Rename-Item -Path "$tinyFolder\sources\install2.wim" -NewName "install.wim" >null
Write-Host "Windows image completed. Continuing with boot.wim."
Start-Sleep -Seconds 2
Clear-Host
Write-Host "Mounting boot image:"
$wimFilePath = "$tinyFolder\sources\boot.wim" 
& takeown "/F" $wimFilePath >null
& icacls $wimFilePath "/grant" "$($adminGroup.Value):(F)"
Set-ItemProperty -Path $wimFilePath -Name IsReadOnly -Value $false
& 'dism' '/English' '/mount-image' "/imagefile:$tinyFolder\sources\boot.wim" '/index:2' "/mountdir:$scratchDir"
Write-Host "Loading registry..."
reg load HKLM\zCOMPONENTS $scratchDir\Windows\System32\config\COMPONENTS
reg load HKLM\zDEFAULT $scratchDir\Windows\System32\config\default
reg load HKLM\zNTUSER $scratchDir\Users\Default\ntuser.dat
reg load HKLM\zSOFTWARE $scratchDir\Windows\System32\config\SOFTWARE
reg load HKLM\zSYSTEM $scratchDir\Windows\System32\config\SYSTEM
Write-Host "Bypassing system requirements(on the setup image):"
& 'reg' 'add' 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' '/v' 'SV1' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' '/v' 'SV2' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' '/v' 'SV1' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' '/v' 'SV2' '/t' 'REG_DWORD' '/d' '0' '/f' >null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassCPUCheck' '/t' 'REG_DWORD' '/d' '1' '/f' >null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassRAMCheck' '/t' 'REG_DWORD' '/d' '1' '/f' >null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassSecureBootCheck' '/t' 'REG_DWORD' '/d' '1' '/f' >null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassStorageCheck' '/t' 'REG_DWORD' '/d' '1' '/f' >null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassTPMCheck' '/t' 'REG_DWORD' '/d' '1' '/f' >null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\MoSetup' '/v' 'AllowUpgradesWithUnsupportedTPMOrCPU' '/t' 'REG_DWORD' '/d' '1' '/f' >null
Write-Host "Tweaking complete!"
Write-Host "Unmounting Registry..."
$regKey.Close()
reg unload HKLM\zCOMPONENTS >null
reg unload HKLM\zDEFAULT >null
reg unload HKLM\zNTUSER >null
reg unload HKLM\zSOFTWARE
reg unload HKLM\zSYSTEM >null
Write-Host "Unmounting image..."
& 'dism' '/English' '/unmount-image' "/mountdir:$scratchDir" '/commit'
Clear-Host
Write-Host "Exporting ESD. This may take a while..."
& dism /Export-Image /SourceImageFile:"$wimFilePath" /SourceIndex:1 /DestinationImageFile:"$tinyFolder\sources\install.esd" /Compress:recovery
Remove-Item "$wimFilePath" -ErrorAction SilentlyContinue
Write-Host "The tiny11 image is now completed. Proceeding with the making of the ISO..."
Write-Host "Copying unattended file for bypassing MS account on OOBE..."
Copy-Item -Path "$PSScriptRoot\autounattend.xml" -Destination "$tinyFolder\autounattend.xml" -Force | Out-Null

Write-Host "Creating ISO image..."
$ADKDepTools = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\$hostarchitecture\Oscdimg"
$localOSCDIMGPath = "$PSScriptRoot\oscdimg.exe"

if ([System.IO.Directory]::Exists($ADKDepTools)) {
    Write-Host "Will be using oscdimg.exe from system ADK."
    $OSCDIMG = "$ADKDepTools\oscdimg.exe"
}
else {
    Write-Host "ADK folder not found. Will be using bundled oscdimg.exe."
    
    
    $url = "https://msdl.microsoft.com/download/symbols/oscdimg.exe/3D44737265000/oscdimg.exe"

    if (-not (Test-Path -Path $localOSCDIMGPath)) {
        Write-Host "Downloading oscdimg.exe..."
        Invoke-WebRequest -Uri $url -OutFile $localOSCDIMGPath

        if (Test-Path $localOSCDIMGPath) {
            Write-Host "oscdimg.exe downloaded successfully."
        }
        else {
            Write-Error "Failed to download oscdimg.exe."
            exit 1
        }
    }
    else {
        Write-Host "oscdimg.exe already exists locally."
    }

    $OSCDIMG = $localOSCDIMGPath
}

& "$OSCDIMG" '-m' '-o' '-u2' '-udfver102' "-bootdata:2#p0,e,b$tinyFolder\boot\etfsboot.com#pEF,e,b$tinyFolder\efi\microsoft\boot\efisys.bin" "$tinyFolder" "$PSScriptRoot\tiny11.iso"

# Finishing up
Read-Host -Prompt "Creation completed! Press any key to exit the script..."
Write-Host "Performing Cleanup before exiting..."
Remove-Item -Path "$tinyFolder" -Recurse -Force | Out-Null
Remove-Item -Path "$scratchDir" -Recurse -Force | Out-Null

# Stop the transcript
Stop-Transcript

exit
