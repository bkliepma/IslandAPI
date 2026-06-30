# Module-wide log folder
$Global:IslandLogFolder = "C:\Temp\Island\Logs"
function Write-Log {
    <#
    .SYNOPSIS
        Writes a formatted log entry to a log file, with rollover support when the file exceeds a specified size.

    .DESCRIPTION
        The Write-Log function creates a log entry with detailed metadata including timestamp, component, context, type, thread ID, and more.
        It supports log file rollover: when the log file exceeds the specified maximum size, it is renamed and a new log file is created.
        The log entry format is compatible with certain log parsers and includes XML-like tags.

    .PARAMETER Message
        The log message to write. This parameter is mandatory.

    .PARAMETER Component
        The component or module name associated with the log entry. Defaults to "Default".

    .PARAMETER Type
        The type of log entry. Valid values are "Info", "Warning", or "Error". Defaults to "Info".

    .PARAMETER LogName
        The base name of the log file (without extension). Defaults to "IslandAPI-General".

    .PARAMETER MaxSize
        The maximum size of the log file in bytes before rollover occurs. Defaults to 200KB.

    .EXAMPLE
        Write-Log -Message "API started successfully." -Component "Startup" -Type "Info"

        Writes an informational log entry for the "Startup" component.

    .EXAMPLE
        Write-Log -Message "Disk space low." -Component "Storage" -Type "Warning" -LogName "SystemMonitor" -MaxSize 100KB

        Writes a warning log entry to the "SystemMonitor.log" file, with a maximum file size of 100KB.

    .NOTES
        Requires: Write-Log function to be defined in the session.
        Requires: The global variable $Global:IslandLogFolder to be set to the desired log folder path.
        Info: Log rollover renames the current log file to "<LogName>.log.old" when the maximum size is exceeded.

    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [String]$Message,

        [Parameter(Mandatory = $false)]
        [String]$Component = "Default",

        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error")]
        [String]$Type = "Info",

        [Parameter(Mandatory = $false)]
        [String]$LogName = "IslandAPI-General",

        [Parameter(Mandatory = $false)]
        [int]$MaxSize = 200KB
    )

    $LogPath = Join-Path $Global:IslandLogFolder ("$LogName.log")
    $Folder = Split-Path -Path $LogPath -Parent
    if (-not (Test-Path -Path $Folder)) {
        New-Item -Path $Folder -ItemType Directory -Force | Out-Null
    }

    switch ($Type) {
        "Info"    { [int]$TypeNum = 1 }
        "Warning" { [int]$TypeNum = 2 }
        "Error"   { [int]$TypeNum = 3 }
    }

    $Content = "<![LOG[$Message]LOG]!>" +
        "<time=`"$(Get-Date -Format "HH:mm:ss.ffffff")`" " +
        "date=`"$(Get-Date -Format "M-d-yyyy")`" " +
        "component=`"$Component`" " +
        "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " +
        "type=`"$TypeNum`" " +
        "thread=`"$([System.Threading.Thread]::CurrentThread.ManagedThreadId)`" " +
        "file=`"`">"

    if (Test-Path -Path $LogPath) {
        $CurrentLog = Get-Item -Path $LogPath
        if ($CurrentLog.Length -gt $MaxSize) {
            $LogPathRollover = "$LogPath.old"
            if (Test-Path -Path $LogPathRollover) {
                Remove-Item -Path $LogPathRollover -Force
            }
            Move-Item -Path $LogPath -Destination $LogPathRollover -Force
        }
    }

    Add-Content -Path $LogPath -Value $Content
}

function Convert-QueryToObjects{
    <#
    .SYNOPSIS
    Returns the active logged in user

    .PARAMETER Name, Computer, ComputerName
    Hostname of the computer to get the active user from. Default is the local computer.

    .EXAMPLE
    Convert-QueryToObjects | ? {$_.SessionState -eq 'Active'}

    .NOTES
    See https://superuser.com/questions/1186568/powershell-get-active-logged-in-user-in-local-machine for origin

    #>
    
[CmdletBinding()]
    [Alias('QueryToObject')]
    [OutputType([PSCustomObject])]
    param
    (
        [Parameter(Mandatory = $false,
                   ValueFromPipeline = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [Alias('ComputerName', 'Computer')]
        [string]
        $Name = $env:COMPUTERNAME
    )

    Process
    {
        Write-Verbose "Running query.exe against $Name."
        $Users = query user /server:$Name 2>&1

        if ($Users -like "*No User exists*")
        {
            # Handle no user's found returned from query.
            # Returned: 'No User exists for *'
            Write-Error "There were no users found on $Name : $Users"
            Write-Verbose "There were no users found on $Name."
        }
        elseif ($Users -like "*Error*")
        {
            # Handle errored returned by query.
            # Returned: 'Error ...<message>...'
            Write-Error "There was an error running query against $Name : $Users"
            Write-Verbose "There was an error running query against $Name."
        }
        elseif ($null -eq $Users -and $ErrorActionPreference -eq 'SilentlyContinue')
        {
            # Handle null output called by -ErrorAction.
            Write-Verbose "Error action has supressed output from query.exe. Results were null."
        }
        else
        {
            Write-Verbose "Users found on $Name. Converting output from text."

            # Conversion logic. Handles the fact that the sessionname column may be populated or not.
            $Users = $Users | ForEach-Object {
                (($_.trim() -replace ">" -replace "(?m)^([A-Za-z0-9]{3,})\s+(\d{1,2}\s+\w+)", '$1  none  $2' -replace "\s{2,}", "," -replace "none", $null))
            } | ConvertFrom-Csv

            Write-Verbose "Generating output for $($Users.Count) users connected to $Name."

            # Output objects.
            foreach ($User in $Users)
            {
                Write-Verbose $User
                if ($VerbosePreference -eq 'Continue')
                {
                    # Add '| Out-Host' if -Verbose is tripped.
                    [PSCustomObject]@{
                        ComputerName = $Name
                        Username = $User.USERNAME
                        SessionState = $User.STATE.Replace("Disc", "Disconnected")
                        SessionType = $($User.SESSIONNAME -Replace '#', '' -Replace "[0-9]+", "")
                    } | Out-Host
                }
                else
                {
                    # Standard output.
                    [PSCustomObject]@{
                        ComputerName = $Name
                        Username = $User.USERNAME
                        SessionState = $User.STATE.Replace("Disc", "Disconnected")
                        SessionType = $($User.SESSIONNAME -Replace '#', '' -Replace "[0-9]+", "")
                    }
                }
            }
        }
    }
}

function get-IslandAPItoken {
<#
.Synopsis
   Returns the API token for Prod or Sandbox, depending on passed parameter.
.Description
   To save tokens, see Save-IslandAPI tokens.
   API token is saved as a secure string to %userprofile%\Documents\WindowsPowerShell\Island and can only be retrieved by the user that saved it.
   I'm not sure if saved tokens can be passed from computer to computer or if they're bound to a single device
.Parameter
    Tenant: accepts "Prod" or "Sandbox;" default is Sandbox
.EXAMPLE
    $token = get-IslandAPItoken -tenant Sandbox
    $token = get-IslandAPItoken -tenant $tenant
#>

    param(
        [ValidateSet("Prod", "Sandbox")]
        [string]$Tenant = "Sandbox"
    )

    #this can be simplified so only the keypath is switched
    switch ($Tenant){
        'Sandbox' {
            $users = Convert-QueryToObjects | Where-Object {$_.SessionState -eq 'Active'}
            $KeypathSB = 'C:\Users\' + $users.Username + '\documents\WindowsPowerShell\Island\SecureKeySB.txt'
            If (Test-Path -Path $KeypathSB){
                #Retrieve Api credentials
                $secureApiKey = Get-Content $KeypathSB | ConvertTo-SecureString

                $apiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureApiKey))
                return $apiKey
            }
            Else{
                Write-host "No API key found for Sandbox. Save a key, or specify another tenant."
                exit
                }
        }
        'Prod' {
            $users = Convert-QueryToObjects | Where-Object {$_.SessionState -eq 'Active'}
            $KeypathProd = 'C:\Users\' + $users.Username + '\documents\WindowsPowerShell\Island\SecureKeyProd.txt'
            If (Test-Path -Path $KeypathProd){
                #Retrieve Api credentials
                $secureApiKey = Get-Content $Keypathprod | ConvertTo-SecureString

                $apiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureApiKey))
                return $apiKey
            }
            Else{
                Write-host "No API key found for Prod. Save a key, or specify another tenant."
                exit
            }
        }
    }
}

#TODO: switch so that returned settings match what are needed for the call type
function get-IslandSettings {
<#
.Synopsis
    Returns API token and host for a specified tenant
.Description
    Also returns headers if a response is expected; I have not tested if it works on something without a returned value
.Parameter
    Tenant: accepts "Prod" or "Sandbox;" default is Sandbox
.EXAMPLE
    $settings = get-IslandSettings -tenant Sandbox
    $settings = get-IslandSettings -tenant $tenant
#>

    param(
        [ValidateSet("Prod", "Sandbox")]
        [string]$Tenant = "Sandbox"
    )
    $islandAPIKey = get-IslandAPItoken($Tenant)
    $islandAPIHost     = 'https://management.island.io'
    $islandAPIheaders  = @{
        'accept'       = 'application/json'
        'api-key'      = $islandAPIKey
        'content-type' = 'application/json'
    }

    $APISettings = @{
        'APIHost'         = $islandAPIHost
        'APIToken'        = $islandAPIKey
        'APIHeaders'      = $islandAPIheaders
    }
    return $APISettings
}

#updated: token handling, passed values
#name and destination URLS required
#Test as written because a lot of the setup got tweaked
#Clean up synopsis
#TODO: modularize message body depending on defines parameters
#Currently, only required parameters are sent
function New-IslandWebApp {
    <#
    .SYNOPSIS
        Creates a new WebApp application in the Island API.

    .DESCRIPTION
        The New-IslandWebApp function connects to the Island API using a provided API key,
        sends a POST request to create a new WebApp application, and logs the process.

    .PARAMETER
        $Tenant (mandatory)
        $AppName (mandatory)
        $AppDescription (validated)
        $AppType (default: custom)
        $AppLogoSVG
        $AppfromBuiltInAppId
        $AppDestinationUrls (mandatory)
        $AppOverwriteDestinationURLs (Why is this both mandatory and default false? Why does it exist at all? this is for new apps.)
        $ApploginUrls

    .EXAMPLE
        New-IslandWebApp

    .NOTES
        Requires: Write-Log function to be defined in the session.
        
    .LINK
        https://documentation.island.io/apidocs/introduction-to-the-api-explorer
    #>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Prod", "Sandbox")]
        $Tenant,
        #App logo is being skipped for the time being until someone works out the logic to require AppData and AppString if AppLogo without false positives
        [Parameter(Mandatory = $true)]$AppName,
        $AppDescription,
        [ValidateSet("WebApp", "SshApp", "RdpApp", "SmbApp", "DesktopApp", "AiApp")]
        $AppType,
        $AppCategory = 'Custom',
        $AppLogoSVG,
        $AppfromBuiltInAppId,
        [Parameter(Mandatory = $true)]$AppDestinationUrls,
        [ValidateSet($true, $false)]
        $AppOverwriteDestinationURLs = $false,
        $ApploginUrls
    )

    Write-Log -Message "Starting New-IslandWebApp function." -Component "New-IslandWebApp" -LogName "IslandAPI-NewWebApp"

    $Settings = get-IslandSettings ($Tenant)
    $islandAPILocation = '/api/external/v1/applications'
    $islandAPIUri      = $settings.APIHost + $islandAPILocation
    $destinationUrls = $AppDestinationUrls -split ',' | ForEach-Object { $_.Trim() }
    Write-Log -Message "Destination URLs parsed: $($destinationUrls -join ', ')" -Component "New-IslandWebApp" -LogName "IslandAPI-NewWebApp"

    $islandAPIbody = @{
        name = $appName
        type = "WebApp"
        category = "Custom"
        #base64Logo = $null
        destinationUrls = $destinationUrls
    } | ConvertTo-Json -Depth 3

    Write-Log -Message "Request body prepared." -Component "New-IslandWebApp" -LogName "IslandAPI-NewWebApp"
    Write-Log -Message $islandAPIbody -Component "New-IslandWebApp" -LogName "IslandAPI-NewWebApp"

    try {
        Write-Log -Message "Sending POST request to $islandAPIUri." -Component "New-IslandWebApp" -LogName "IslandAPI-NewWebApp"
        $islandAPIResponse = Invoke-RestMethod -Method Post -Uri $islandAPIUri -Headers $settings.APIHeaders -Body $islandAPIbody
        Write-Log -Message "POST request successful." -Component "New-IslandWebApp" -LogName "IslandAPI-NewWebApp"
        Write-Log -Message $islandAPIResponse -Component "New-IslandWebApp" -LogName "IslandAPI-NewWebApp"
    }
    catch {
        Write-Log -Message "POST request failed: $($_.Exception.Message)" -Component "New-IslandWebApp" -Type "Error" -LogName "IslandAPI-NewWebApp"
        If ($_.Exception.Message -like "*(400) Bad Request*")
        {
            Test-IslandWebApp -Tenant $Tenant -AppName $AppName -AppDestinationUrls $AppDestinationUrls -AppOverwriteDestinationURLs $false
        }
    }
}

#update synopsis
function Test-IslandWebApp{
    <#
    .SYNOPSIS
        Creates a new WebApp application in the Island API.

    .DESCRIPTION
        The New-IslandWebApp function connects to the Island API using a provided API key,
        sends a POST request to create a new WebApp application, and logs the process.

    .PARAMETER
        $Tenant (mandatory)
        $AppName (mandatory)
        $AppDescription (validated)
        $AppType (default: custom)
        $AppLogoSVG
        $AppfromBuiltInAppId
        $AppDestinationUrls (mandatory)
        $AppOverwriteDestinationURLs (Why is this both mandatory and default false? Why does it exist at all? this is for new apps.)
        $ApploginUrls

    .EXAMPLE
        New-IslandWebApp

    .NOTES
        Requires: Write-Log function to be defined in the session.
        
    .LINK
        https://documentation.island.io/apidocs/introduction-to-the-api-explorer
    #>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Prod", "Sandbox")]
        $Tenant,
        #App logo is being skipped for the time being until someone works out the logic to require AppData and AppString if AppLogo without false positives
        [Parameter(Mandatory = $true)]$AppName,
        $AppDescription,
        [ValidateSet("WebApp", "SshApp", "RdpApp", "SmbApp", "DesktopApp", "AiApp")]
        $AppType,
        $AppCategory = 'Custom',
        $AppLogoSVG,
        $AppfromBuiltInAppId,
        [Parameter(Mandatory = $true)]$AppDestinationUrls,
        [ValidateSet($true, $false)]
        $AppOverwriteDestinationURLs = $false,
        $ApploginUrls
    )
    Write-Log -Message "Trying Get-IslandApps to find existing app" -Component "New-IslandWebApp" -Type "Error" `
        -LogName "IslandAPI-NewWebApp"
    $apps = Get-IslandApps -Tenant $Tenant -Type WebApp
    $found = $false
    foreach($app in $apps)
    { 
        Write-Host $app.name
        If($app.name -like $AppName)
        {
            $found = $true
            try 
            {
                $updateapp = Read-host "Web app " $AppName " already exists on " $Tenant ". Update? (y/n)"
                If (($updateapp -eq 'y') -or ($updateapp -eq 'yes'))
                {
                    Write-Host "Trying Update-IslandWebApp instead."
                    Update-IslandWebApp -Tenant $Tenant -AppID $app.id -AppName $AppName -AppDestinationUrls $AppDestinationUrls `
                        -AppOverwriteDestinationURLs $false
                    Write-host "Back after Update-IslandWebApp"
                }
                Else {Write-host "Not updating existing app per response"}
            }
            catch 
            {
                Write-host "Failed to create new app."
                Write-Log -Message "POST request failed: $($_.Exception.Message)" -Component "New-IslandWebApp" -Type "Error" -LogName "IslandAPI-NewWebApp"   
            }
        }
    }
    If ($found -eq $false)
    {Write-Log -Message "No existing app found." -Component "New-IslandWebApp" -Type "Error" -LogName "IslandAPI-NewWebApp"}
}

function Get-IslandAppByID {
<#
.Synopsis
    Returns app when called by ID
.Description
    Better option is Get all Custom Web Applications
    https://documentation.island.io/apidocs/get-all-applicationlibrary-entities
.Parameter
    Tenant: accepts "Prod" or "Sandbox"
    AppID (mandatory)
.EXAMPLE
    $settings = Get-IslandAppByID -tenant Sandbox -AppID <appID>
    $settings = Get-IslandAppByID -tenant $tenant -AppID <appID>
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)][ValidateSet("Prod", "Sandbox")]$Tenant,
        [Parameter(Mandatory = $true)]$AppID
        )
        
    #APItoken
    Write-Log -Message "Starting Get-IslandAppByID." -Component "Get-IslandAppByID" -LogName "IslandAPI-Get-IslandAppByID"
    #$islandAPIKey = get-IslandAPItoken ($Tenant)
    #Write-Log -Message "API Key retrieved." -Component "Get-IslandAppByID" -LogName "IslandAPI-Get-IslandAppByID"
    #the actual apitoken retrieval should be in get-islandsettings
    
    #headers
    $Settings = get-IslandSettings ($Tenant)
    $islandAPILocation = '/api/external/v1/applications/' + $AppID
    $islandAPIUri      = $settings.APIHost + $islandAPILocation
    #message body
        
    #POST
    try {
        Write-Log -Message "Sending POST request to $islandAPIUri."  -Component "Get-IslandAppByID" -LogName "IslandAPI-Get-IslandAppByID"
        $islandAPIResponse = Invoke-RestMethod -Method Get -Uri $islandAPIUri -Headers $settings.APIHeaders -Body $islandAPIbody
        Write-Log -Message "Get request successful." -Component "Get-IslandAppByID" -LogName "IslandAPI-Get-IslandAppByID"
        #$islandAPIResponse
    }
    catch {
        Write-Log -Message "GET request failed: $($_.Exception.Message)" -Component "Get-IslandAppByID" -LogName "IslandAPI-Get-IslandAppByID"
        $_.Exception.Message
    }
    return $islandAPIResponse
    Write-Log -Message "Get-IslandWebApp function completed." -Component "Get-IslandAppByID" -LogName "IslandAPI-Get-IslandAppByID"
}

Function Update-IslandWebApp {
<#
.Synopsis
    Updates/modifies an existing web app
.Description
    Properly speaking, this overwrites an existing app by name; nothing but the name and ID are retained by default when calling this method.
    App logo is getting skipped until someone works out the logic and parameter set for it 
.Parameter
    Tenant (mandatory, validated)
    AppID (mandatory)
    AppName (mandatory)
    AppDescription 
    AppType (validated)
    AppLogoSVG
    AppfromBuiltInAppId
    AppDestinationUrls (mandatory)
    AppOverwriteDestinationURLs (mandatory, validated, default false)
    ApploginUrls
.EXAMPLE
    Update-IslandWebApp -Tenant Sandbox -AppID <ID> -AppName Name -AppDestinationUrls "urls, separated by commas" -AppOverwriteDestinationURLs $false
#>
    param(
        [Parameter(Mandatory = $true)][ValidateSet("Prod", "Sandbox")] $Tenant,
        [Parameter(Mandatory = $true)]$AppID,
        [Parameter(Mandatory = $true)]$AppName,
        $AppDescription,
        [ValidateSet("WebApp", "SshApp", "RdpApp", "SmbApp", "DesktopApp", "AiApp")] $AppType,
        $AppCategory = 'Custom',
        $AppLogoSVG,
        $AppfromBuiltInAppId,
        [Parameter(Mandatory = $true)] $AppDestinationUrls,
        [ValidateSet($true, $false)] $AppOverwriteDestinationURLs = $false,
        $ApploginUrls
        #App logo is being skipped until someone works out the logic to require AppData and `
            #AppString if AppLogo without false positives
        )
    
    #APItoken
    Write-Log -Message "Starting Update-IslandWebApp." -Component "Update-IslandWebApp" -LogName "IslandAPI-UpdateIslandWebApp"

    #Get existing destinationURLs so they aren't overwritten
    If(-not $AppOverwriteDestinationURLs){
        try {
            $originalURLs = Get-IslandAppByID -Tenant $Tenant -AppID $AppID
            $AppDestinationUrls = $originalURLs.destinationUrls + $AppDestinationUrls
        }
        catch {
            Write-host $_.Exception.Message ############todo: logging?
        }
    }

    #settings and headers
    $Settings = get-IslandSettings ($Tenant)
    $islandAPILocation = '/api/external/v1/applications/' + $AppID
    $islandAPIUri      = $settings.APIHost + $islandAPILocation
    $destinationUrls = $AppDestinationUrls -split ',' | ForEach-Object { $_.Trim() }
    $loginUrls = $ApploginUrls -split ',' | ForEach-Object { $_.Trim() }

    #message body
    Write-Log -Message "Destination URLs parsed: $($destinationUrls -join ', ')" -Component "Update-IslandWebApp" -LogName "IslandAPI-UpdateIslandWebApp"
    Write-Log -Message "Login URLs parsed: $($loginUrls -join ', ')" -Component "Update-IslandWebApp" -LogName "IslandAPI-UpdateIslandWebApp"
        
    $islandAPIbody = @{
        name            = $appName
        #description     = $AppDescription
        #type            = $AppType
        category        = $AppCategory
        #logoSvg         = $AppLogoSVG
        destinationUrls = $destinationUrls
        #loginUrls       = $loginUrls
    } | ConvertTo-Json -Depth 3
    Write-Log -Message "Request body prepared." -Component "Update-IslandWebApp" -LogName "IslandAPI-UpdateIslandWebApp"
    Write-Log -Message $islandAPIbody -Component "Update-IslandWebApp" -LogName "IslandAPI-UpdateIslandWebApp"

    #PATCH
    try {
        Write-Log -Message "Sending PATCH request to $islandAPIUri." -Component "Update-IslandWebApp" -LogName "IslandAPI-UpdateIslandWebApp"
        $islandAPIResponse = Invoke-RestMethod -Method Patch -Uri $islandAPIUri -Headers $settings.APIHeaders -Body $islandAPIbody
        Write-Log -Message "PATCH request successful." -Component "Update-IslandWebApp" -LogName "IslandAPI-UpdateIslandWebApp"
        Write-Log -Message $islandAPIResponse -Component "Update-IslandWebApp" -LogName "IslandAPI-UpdateIslandWebApp"
    }
    catch {
        Write-Log -Message "POST request failed: $($_.Exception.Message)" -Component "Update-IslandWebApp" -LogName "IslandAPI-UpdateIslandWebApp"
    }
    Write-Log -Message "Update-IslandWebApp function completed." -Component "Update-IslandWebApp" -LogName "IslandAPI-UpdateIslandWebApp"

}

#
function Get-IslandPendingChanges {
    <#
    .SYNOPSIS
        Retrieves pending policy changes from the Island API.

    .DESCRIPTION
        The Get-IslandPendingChanges function connects to the Island API using a provided API key,
        sends a GET request to retrieve pending policy changes, and logs the process.
        If pending changes are found, it warns the user and provides a link to the Admin Events page.

    .PARAMETER
        Tenant (mandatory, validated)

    .EXAMPLE
        Get-IslandPendingChanges -tenant Sandbox

        Checks for pending changes and logs the results.

    .NOTES
        Requires: Write-Log function to be defined in the session.

    .LINK
        https://documentation.island.io/apidocs/introduction-to-the-api-explorer
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet("Prod", "Sandbox")] $Tenant
    )
    Write-Log -Message "Starting Get-IslandPendingChanges function." -Component "Get-IslandPendingChanges" -LogName "IslandAPI-PendingChanges"

    #APItoken
    $Settings = get-IslandSettings ($Tenant)
    
    $islandAPILocation = '/api/external/v1/policyChanges/pendingChanges'
    $islandAPIUri      = $Settings.APIHost + $islandAPILocation
    $islandAPIheaders  = @{
        'accept'       = 'application/json'
        'api-key'      = $Settings.APIToken
    }

    try {
        Write-Log -Message "Sending GET request to $islandAPIUri." -Component "Get-IslandPendingChanges" -LogName "IslandAPI-PendingChanges"
        $Settings.APIHeaders
        $islandAPIResponse = Invoke-RestMethod -Method GET -Uri $islandAPIUri -Headers $islandAPIheaders
        Write-Log -Message "GET request successful." -Component "Get-IslandPendingChanges" -LogName "IslandAPI-PendingChanges"
    }
    catch {
        Write-Log -Message "GET request failed: $($_.Exception.Message)" -Component "Get-IslandPendingChanges" -Type "Error" -LogName "IslandAPI-PendingChanges"
        $_.Exception.Message
        If($_.Exception.Message -like '*(403) Forbidden*')
        {
            Write-Warning "The API token used does not have sufficient permission to read pending changes. Try another token."
        }
    }

    if ($islandAPIResponse.actionStatus -eq "Pending") {
        Write-Log -Message "There are pending changes to be applied." -Component "Get-IslandPendingChanges" -Type "Warning" -LogName "IslandAPI-PendingChanges"
        Write-Warning "Pending Changes found please check Admin Events - https://management.island.io/sanfordhealth/system-settings/admin-management/adminAudit"
    }
    else {
        Write-Log -Message "No pending changes found." -Component "Get-IslandPendingChanges" -LogName "IslandAPI-PendingChanges"
        return "No pending changes found."
    }
    Write-Log -Message "Get-IslandPendingChanges function completed." -Component "Get-IslandPendingChanges" -LogName "IslandAPI-PendingChanges"
}

#Verified 6/29/26
function Get-IslandUsers {
    <#
    .SYNOPSIS
        Retrieves users from the Island API.

    .DESCRIPTION
        The Get-IslandUsers function connects to the Island API using a provided API key,
        sends a GET request to retrieve user information, and logs the process.
        Supports filtering and property selection for output.
        The function also ensures the API key is cleared from memory after use.

    .PARAMETER Properties
        Array of user properties to display. Defaults to lastName, firstName, email, userSource, id.

    .PARAMETER FilterProperty
        Property name to filter users by.

    .PARAMETER FilterValue
        Value to filter the specified property by.

    .EXAMPLE
        Get-IslandUsers

        Prompts for the Island API key, retrieves all users, and logs the results.

    .EXAMPLE
        Get-IslandUsers -FilterProperty "email" -FilterValue "example.com"

        Retrieves users whose email matches "example.com".

    .NOTES
        Requires: Write-Log function to be defined in the session.

    .LINK
        https://documentation.island.io/apidocs/introduction-to-the-api-explorer
    #>
    param (
        [Parameter(Mandatory = $true)][ValidateSet("Prod", "Sandbox")] $Tenant,
        [string[]]$Properties = @('lastName','firstName','email','userSource','id'),
        [string]$FilterProperty,
        [string]$FilterValue
    )

    #limiting the api settings to the token because get-apisettings isn't set up for this
    $islandAPIKey = get-IslandAPItoken -Tenant $Tenant
    $islandAPIHost = 'https://management.island.io'
    $islandAPILocation = '/api/external/v1/users'
    $islandAPIQueryParams = '?Limit=1000&SortBy=UserType&IncludeAllUserStatus=true'
    $islandAPIUri = $islandAPIHost + $islandAPILocation + $islandAPIQueryParams
    $islandAPIheaders = @{
        'accept'  = 'application/json'
        'api-key' = $islandAPIKey
    }

    try {
        Write-Log -Message "Attempting to make API call to get Island users" -Component "Get Users" -LogName "IslandAPI-GetUsers"
        $islandAPIResponse = Invoke-RestMethod -Uri $islandAPIUri -Method GET -Headers $islandAPIheaders -ErrorAction Stop
        Write-Log -Message "API call completed with no errors" -Component "Get Users" -LogName "IslandAPI-GetUsers"
    } catch {
        Write-Log -Message "An error occurred making API call" -Component "Get Users" -Type Error -LogName "IslandAPI-GetUsers"
        Write-Log -Message "$($_.Exception.Message)" -Component "Get Users" -Type Error -LogName "IslandAPI-GetUsers"
        return
    }

    if ($islandAPIResponse -and $islandAPIResponse.users) {
        if ($islandAPIResponse.users.Count -eq 0) {
            Write-Log -Message "No users found in API response" -Component "Get Users" -Type Warning -LogName "IslandAPI-GetUsers"
            Write-Host "No users found."
            return
        }
        $filteredUsers = if ($FilterProperty -and $FilterValue) {
            $islandAPIResponse.users | Where-Object { $_.$FilterProperty -match $FilterValue }
        } else {
            $islandAPIResponse.users
        }
        if ($filteredUsers.Count -eq 0) {
            Write-Log -Message "No users found after filtering" -Component "Get Users" -Type Warning -LogName "IslandAPI-GetUsers"
            Write-Host "No users found."
            return
        }
        Write-Log -Message "Outputting filtered list of users to host" -Component "Write-Host" -LogName "IslandAPI-GetUsers"
        $filteredUsers |
            Select-Object -Property $Properties |
            Sort-Object -Property lastName |
            Format-Table -AutoSize |
            Out-String |
            Write-Host
    } else {
        Write-Log -Message "No user data received from API call" -Component "Get Users" -Type Warning -LogName "IslandAPI-GetUsers"
    }

}

#Verified 6/29/26
function Get-IslandApps {
    <#
    .SYNOPSIS
        Retrieves Island applications from the Island API.

    .DESCRIPTION
        The Get-IslandApps function connects to the Island API using a provided API key,
        sends a GET request to retrieve all applications, and logs the process.
        You can filter results by application type. The function ensures the API key is cleared from memory after use.

    .PARAMETER Type
        Optionally specify the application type to filter results. Valid values: WebApp, SshApp, RdpApp, SmbApp, DesktopApp.

    .EXAMPLE
        Get-IslandApps
        Prompts for the Island API key, retrieves all Island applications, and logs the results.

    .EXAMPLE
        Get-IslandApps -Type WebApp
        Prompts for the Island API key, retrieves only WebApp applications, and logs the results.

    .NOTES
        Requires: Write-Log function to be defined in the session.

    .LINK
        https://documentation.island.io/apidocs/introduction-to-the-api-explorer
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)][ValidateSet("Prod", "Sandbox")] $Tenant,
        [Parameter(Mandatory = $false)]
        [ValidateSet("WebApp", "SshApp", "RdpApp", "SmbApp", "DesktopApp")]
        [String]$Type
        )

    #settings and headers
    $settings = get-IslandSettings -Tenant $Tenant
    $islandAPILocation = '/api/external/v1/applications'
    $islandAPIQueryParams = '?includeType=Default'
    $islandAPIUri = $settings.APIHost + $islandAPILocation + $islandAPIQueryParams
    $islandAPIheaders = @{
      'accept'  = 'application/json'
      'api-key' = $settings.APIToken
    }

    #GET
    try {
        Write-Log -Message "Attempting to make API call to get all Island apps" -Component "Get All Apps" -LogName "IslandAPI-GetApps"
        $islandAPIResponse = Invoke-RestMethod -Uri $islandAPIUri -Method GET -Headers $islandAPIheaders -ErrorAction Stop
        Write-Log -Message "Found a total of $($islandAPIResponse.Count) apps" -Component "Get All Apps" -LogName "IslandAPI-GetApps"
    } catch {
        Write-Log -Message "An error occured making API call" -Component "Get All Apps" -Type Error -LogName "IslandAPI-GetApps"
        Write-Log -Message "$_ " -Component "Get All Apps" -Type Error -LogName "IslandAPI-GetApps"
        return
    }
    
    if ($Type) {
        $islandApps = ($islandAPIResponse | Where-Object { $_.Type -eq $Type } | Select-Object -Property name,id)
    } else {
        $islandApps = $islandAPIResponse #| Select-Object -Property name,id,Type)
    }
    
    if ($islandApps) {
        if ($Type) {
            Write-Log -Message "Found $($islandApps.count) $($Type)s" -Component "Get $($Type)s" -Type Warning -LogName "IslandAPI-GetApps"
        } else {
            Write-Log -Message "Found $($islandApps.count) apps (all types)" -Component "Get All Apps" -Type Warning -LogName "IslandAPI-GetApps"
        }
        return $islandApps
    } else {
        if ($Type) {
            Write-Log -Message "Found 0 $($Type)s" -Component "Get $($Type)s" -Type Warning -LogName "IslandAPI-GetApps"
            return "No $($Type)s found"
        } else {
            Write-Log -Message "Found 0 apps" -Component "Get All Apps" -Type Warning -LogName "IslandAPI-GetApps"
            return "No apps found"
        }
    }
}

#Verified 6/29/26
function save-IslandAPItoken {
<#
.SYNOPSIS
    Securely saves API key for the specified tenant to 'C:\Users\' + $users.Username + '\documents\WindowsPowerShell\Island'

.DESCRIPTION
    File is only decipherable by the user that encrypts it.
    Prod is saved as SecureKeyProd.txt
    Sandbox is saved as SecureKeySB.txt

.PARAMETER Type
    Tenant (validated)
    API (mandatory)
    $Update (validated)

.EXAMPLE
    save-IslandAPItoken -Tenant Sandbox -API <token> -Update False

.LINK
    https://evelin.tech/store-api-keys-securely-with-powershell/
#>

    param(
        [ValidateSet("Prod", "Sandbox")]
        $Tenant = "Sandbox",
        [Parameter(Mandatory = $true)]
        $API,
        [ValidateSet($true,$false)]
        $Update = $false
    )

    $users = Convert-QueryToObjects | Where-Object {$_.SessionState -eq 'Active'}
    $IslandPath = 'C:\Users\' + $users.Username + '\documents\WindowsPowerShell\Island'

    #create  Island folder if it doesn't exist
    If (!(Test-Path $IslandPath)){New-Item -ItemType Directory -Path $IslandPath}
    
    switch ($Tenant){###############
        'Prod'{$Keypath = $IslandPath + '\SecureKeyProd.txt'}
        'Sandbox'{$Keypath =  $IslandPath + '\SecureKeySB.txt'}
    }
    #if the keyfile already exists, ask if it needs updating. If it doesn't exist, create file, save API
    If((Test-Path $Keypath) -and (($Update -eq $false))){
        $UpdateKey = Read-Host $Tenant " key is already saved. Do you want to update it? (Y/N) "
        If(($UpdateKey -eq 'yes') -or ($UpdateKey -eq 'y') ){
            #Store Api credentials
            Write-host $Keypath
            #$apiKey = Read-Host "Enter your Island API key for " $tenant
            $password = ConvertTo-SecureString $api -AsPlainText -Force
            $password | ConvertFrom-SecureString | Out-File $Keypath
        }
        Else{Write-Host "Skipping" $Tenant "key ..."}
    }
    Else{  #####################ignores update          
        #Store Api credentials
        #$apiKey = Read-Host "Enter your Island API key for " $Tenant
        $password = ConvertTo-SecureString $api -AsPlainText -Force
        $password | ConvertFrom-SecureString | Out-File $Keypath
    }
}

#TODO other filters? since date? 
#Current WIP
#LOG
#ERROR CHECKING
#Not committing after; do that manually *Add later as option
<# Cut down to only go from Prod to SB
from SB to Prod should be Migrate app by ID#>
function Sync-IslandWebApps{
    <#
    .SYNOPSIS
        Copies/syncs from Prod to Sandbox
        

    .DESCRIPTION
        For promotion from SB to Prod, use Migrate-IslandWebAppByID
        TODO: backup and wipe SB before loading from prod (separate functions, called from here)

    .PARAMETER Type
        Tenant (validated)
        API (mandatory)
        $Update (validated)

    .EXAMPLE
        save-IslandAPItoken -Tenant Sandbox -API <token> -Update False

    .LINK
        https://evelin.tech/store-api-keys-securely-with-powershell/
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Prod", "Sandbox")]$Source,
        [Parameter(Mandatory = $true)]
        [ValidateSet("Prod", "Sandbox")]$Destination,
        [ValidateSet($true, $false)]$OverwriteExistingApp = $false#,
        #[ValidateSet($true, $false)]$Confirm = $false,
        #[ValidateSet($true, $false)]$ConfirmEach = $false
        #TODO See if -Confirm flag is built in 
    )
    $SourceApps = Get-IslandApps -Tenant $Source 
    $DestinationApps = Get-IslandApps -Tenant $Destination
    foreach($app in $SourceApps){
        If($OverwriteExistingApp)
        {
            New-IslandWebApp -Tenant $Source -AppName $app.name -AppDescription $app.Description -AppType $app.type `
                -AppCategory $app.category -AppLogoSVG $app.svg -AppDestinationUrls $app.destinationUrls `
                -ApploginUrls $app.loginUrls 
        }
        Elseif ($app.name -notin $DestinationApps.name){$DestinationTemp.apps.add($app) }
    }

    If ($DestinationTemp){
        foreach ($app in $DestinationTemp){
            If($PSCmdlet.ShouldProcess("Console", "Creating '$app.name' on '$tenant' with settings -AppDescription '$app.Description' `
                -AppType '$app.type' -AppCategory '$app.category' -AppLogoSVG '$app.svg' -AppDestinationUrls '$app.destinationUrls' `
                -ApploginUrls '$app.loginUrls'")){
                    New-IslandWebApp -Tenant $Destination -AppName $app.name -AppDescription $app.Description -AppType $app.type `
                        -AppCategory $app.category -AppLogoSVG $app.svg -AppDestinationUrls $app.destinationUrls -ApploginUrls $app.loginUrls 
            }
        }
    }
}

<#
Export app
add optional passed values
Approve pending changes (can I issue an API token that approves changes in prod if I don't have perms to approve changes? YES) 
update app (do changes need applying first)
change api token/"i have tested this in SB; export to prod"
merge to SB/prod
https://documentation.island.io/apidocs/get-all-admin-actions-that-match-the-specified-complex-filter
>get all actions for last XX days/from Y user, export, import to sb

test: does this SB match prod? prompt for update
save/set preferences (Save/use API key, sb/prod default, ???)
#>
<#TODO
Backup (keys, tenant, apps)
Wipe (limited to SB)
Sync should have option to wipe and reload
get pending changes gets user, apply pending changes gest user, if match, fails *require peer review
can api keys be revoked via api?

#>
#WIP
#Needs synopsis
#TODO parameter set to migrate by name or ID
#TODO Did you use AppOverwriteDestinationURLs?
#Did you check if source and destination are different?
<#update get-apisettings to allow for different requirements
*What are those requirements and how are they set
add to app group (finish adding web app)
git sync


#>
function Move-IslandWebAppByID{ #This is for copying from SB to prod; fix
<#
    .SYNOPSIS
        Copies an app from Sandbox to Prod

    .DESCRIPTION
        Intended for promotion to Prod

    .PARAMETER Type
        $Source (Mandatory)
        $Destination (Mandatory)
        $AppID (Mandatory)
        $AppName,
        $AppDescription,
        $AppType [Validated("WebApp", "SshApp", "RdpApp", "SmbApp", "DesktopApp", "AiApp")]
        $AppCategory = 'Custom',
        $AppLogoSVG,
        $AppfromBuiltInAppId,
        $AppDestinationUrls,
        $ApploginUrls [Validated($true, $false)][Parameter(Mandatory = $true)]
        $AppOverwriteDestinationURLs = $false,
        $VerifyAppByName [Validated($true, $false)]
        $OverwriteExistingApp [Validated($true, $false)] = $false

    .EXAMPLE

    .EXAMPLE

    .NOTES
        Requires: Write-Log function to be defined in the session.

    .LINK
        https://documentation.island.io/apidocs/introduction-to-the-api-explorer
    #>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Prod", "Sandbox")]
        [string]$Source,
        [Parameter(Mandatory = $true)]
        [ValidateSet("Prod", "Sandbox")]
        [string]$Destination,
        [Parameter(Mandatory = $true)]$AppID,
        $AppName,
        $AppDescription,
        [ValidateSet("WebApp", "SshApp", "RdpApp", "SmbApp", "DesktopApp", "AiApp")]
        $AppType,
        $AppCategory = 'Custom',
        $AppLogoSVG,
        $AppfromBuiltInAppId,
        $AppDestinationUrls,
        [ValidateSet($true, $false)][Parameter(Mandatory = $true)]$AppOverwriteDestinationURLs = $false,
        $ApploginUrls,
        [ValidateSet($true, $false)]$VerifyAppByName,
        [ValidateSet($true, $false)]$OverwriteExistingApp = $false
    )
    if ($VerifyAppByName){
        $SourceWebApp = Get-IslandAppByID -Tenant $source -AppID $AppID 
        write-Host "The AppID provided belongs to " $SourceWebApp.name
        $Verified = Read-host "Is this correct? (Y/N)"
        If (($Verified -ne 'yes') -and ($Verified -ne 'y')) {exit}
    }
    $DestinationWebApp = Get-IslandAppByID -Tenant $Destination -name $SourceWebApp.name

    #if we are overwriting the existing app and it doesn't exist, new
    #if we are not overwriting the existing app and it doesn't exist, new
    If (-not $DestinationWebApp){ 
        New-IslandWebApp -Tenant $destination -name $ExistingWebApp.name -description $ExistingWebApp.description -type $ExistingWebApp.type `
            -category $ExistingWebApp.category -logoSvg $ExistingWebApp.logosvg -fromBuiltInAppId $ExistingWebApp.BuiltInApp `
            -destinationUrls $ExistingWebApp.destinationUrls -loginUrls $ExistingWebApp.loginUrls
    }

    #if we are overwriting the existing app and it exists, update/overwrite 
    elseif (($OverwriteExistingApp -eq 'yes') -or ($OverwriteExistingApp -eq 'y')){
        Update-IslandWebApp -Tenant $destination -name $SourceWebApp.name -description $SourceWebApp.description -type $SourceWebApp.type `
            -category $SourceWebApp.category -logoSvg $SourceWebApp.logosvg -fromBuiltInAppId $SourceWebApp.BuiltInApp `
            -destinationUrls $SourceWebApp.destinationUrls -loginUrls $SourceWebApp.loginUrls 
        }

    ###if we are not overwriting the existing app and it exists, merge the destination urls
    elseif (($OverwriteExistingApp -ne 'yes') -and ($OverwriteExistingApp -ne 'y')){
        Write-Host $DestinationWebApp.name " already exists in " $Destination " and the `
            OverwriteExistingApp parameter was not Yes. Destination URLs will be merged. Other settings will be updated."
        foreach($url in $DestinationWebApp.destinationUrls)
            {if ($DestinationWebApp.destinationUrls -notcontains $url)
                {$SourceWebApp.destinationUrls.Add($url)}}
        Update-IslandWebApp -Tenant $destination -name $SourceWebApp.name -description $SourceWebApp.description -type $SourceWebApp.type `
            -category $SourceWebApp.category -logoSvg $SourceWebApp.logosvg -fromBuiltInAppId $SourceWebApp.BuiltInApp `
            -destinationUrls $SourceWebApp.destinationUrls -loginUrls $SourceWebApp.loginUrls 
    }
}

