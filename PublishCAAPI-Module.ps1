
cls
$tenantDomain = 'identt.work' #change your tenant domain
$clientID = 'd9952f13-0ebe-468b-a44e-ba7e99bebcf0'  #change to your AppID

Import-Module MSCloudIdUtils
#$accessToken = Get-MSCloudIdAccessTokenFromUser -TenantDomain $tenantDomain -ClientId $clientID -Resource 'https://canary.graph.microsoft.com' -RedirectUri 'urn:ietf:wg:oauth:2.0:oob' 

$authHeaders = New-Object 'System.Collections.Generic.Dictionary[[String],[String]]'
$authHeaders.Add('Authorization', 'Bearer ' + $accessToken)
$authHeaders.Add('Content-Type','application/json')
$authHeaders.Add('Accept','application/json, text/plain')
$baseURI = 'https://canary.graph.microsoft.com/testidentityprotectionservices/conditionalaccesspolicies/'



function Get-CAPolicy{
        Param(
            [Parameter(mandatory=$true)]
            [string]$PolicyID
        )
            
    $uri1  = $baseURI + "/" + $PolicyID
    $resp1 = Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $uri1 -Method Get
    $val1  = ConvertFrom-Json $resp1.Content
    $PolicyJSON =$val1 | ConvertTo-Json -Depth 10  
    return $PolicyJSON
}

function Start-CAPolicyBackup{
        Param(
            [Parameter(mandatory=$true)]
            [string]$ExportFileName
        )
            
    $uri1  = $baseURI  
    $resp1 = Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $uri1 -Method Get
    $val1  = ConvertFrom-Json $resp1.Content
    $val1  | ConvertTo-Json -Depth 10  | Out-File $ExportFileName
}

function New-CAPolicy{
            Param(
                [Parameter(mandatory=$true)]
                [string]$PolicyJSONString
                
            )
            $uri1  = $baseURI
            $resp1 = Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $uri1 -Method POST -Body $PolicyJSONString 
            $returnMessage = ConvertFrom-Json $resp1.Content
            return $returnMessage
}

function Start-CAPolicyRestore{
           Param(
                [Parameter(mandatory=$true)]
                [string]$PolicyBackupFile,                
                [ValidateSet("Enabled","Disabled")][String]$State 
                
            )
      
        
        $json= Get-Content -Path $PolicyBackupFile -Raw | ConvertFrom-Json 
        foreach( $jsonObject in $json.value)
        {
            $jsonObject.PSObject.Properties.Remove('id')
            $jsonObject.PSObject.Properties.Remove('createdDateTime')
            $jsonObject.PSObject.Properties.Remove('modifiedDateTime')
            $RestoredDisplayName=($jsonObject.displayName.ToString() + " (Restored from Backup)")
            $jsonObject.displayName=$RestoredDisplayName
            $jsonObject.state = $State
            $PolicyString = $jsonObject  | ConvertTo-Json -depth 10 -Compress
            $returncode = New-CAPolicy -PolicyJSONString $PolicyString
            Write-Host "$returncode"
        }
                                                                   

}

function Get-CAPolicySection{
        Param(
            
            [ValidateSet("conditions","grantControls")][String]$SectionNameInput,
            [Parameter(mandatory=$true)]
            [String] $PolicyJSON
            )
            

        ##Future check JSON Policy
        $sectionNamePadding='":'
        $SectionName=$SectionNameInput+$sectionNamePadding
        $sectionStart='{'
        $sectionEnd='}'

        $SectionStartPosition=0
        $SectionEndPosition=0


        $SectionStartPosition= $PolicyJSON.IndexOf($SectionName) + $SectionName.Length
        $SectionStartPositionMark=$SectionStartPosition
        
        

        $endOfSection=$false
        $NestedSection=0
        
        while( $endOfSection -ne $true)
        {
            $nextSectionStartTokenPosition = $PolicyJSON.IndexOf($sectionStart,$SectionStartPosition)
            $nextSectionEndTokenPosition   = $PolicyJSON.IndexOf($sectionEnd,$SectionStartPosition)
            

            ### If there is no subsection {} the index for { is -1
            if($nextSectionStartTokenPosition -lt 0 )
            {
                $SectionStartPosition=$nextSectionEndTokenPosition+1
                $SectionEndPositionMark=$nextSectionEndTokenPosition+1
                $endOfSection=$true
            }
            
            
            ## If the end appears before start its the end of section
            ## Else there is a child section
            if($nextSectionStartTokenPosition -lt $nextSectionEndTokenPosition)
            {
                $NestedSection++  
                $SectionStartPosition =  $nextSectionStartTokenPosition+1
            }
            if($nextSectionEndTokenPosition -lt $nextSectionStartTokenPosition)
            {
                $NestedSection--        
                $SectionStartPosition=$nextSectionEndTokenPosition+1
                $SectionEndPositionMark=$nextSectionEndTokenPosition+1
            }

            if($NestedSection -le 0)
            {
                $endOfSection=$true
            }
            
        }


        $Result=$PolicyJSON.Substring($SectionStartPositionMark,$SectionEndPositionMark-$SectionStartPositionMark)
        return $Result
}

function Set-CAPolicy{
        Param(
            [Parameter(mandatory=$true)]
            [string]$PolicyID,
            [string]$DisplayName,
            [ValidateSet("Enabled","Disabled")][String]$State,
            [ValidateSet("High","Medium","Low","None")][String[]]$signInRiskLevels,
            [ValidateSet("Browser","Modern","EasSupported","EasUnsupported","None")][String[]]$ClientAppsTypes,
            [ValidateSet("All","Android","Ios","Windows","WindowsPhone","MacOs")][String[]]$includePlatforms,
            [ValidateSet("All","Android","Ios","Windows","WindowsPhone","MacOs")][String[]]$excludePlatforms,
            [String[]]$includeLocations,
            [String[]]$excludeLocations,
            [ValidateSet("All")][String]$includeDeviceStates,
            [ValidateSet("Compliant","DomainJoined")][String[]]$excludeDeviceStates,
            [String[]]$includeUsers,
            [String[]]$excludeUsers,
            [String[]]$includeGroups,
            [String[]]$excludeGroups,
            [String[]]$includeRoles,
            [String[]]$excludeRoles

        )

        $lenr=$includeLocations.length
        write-host "IncludeLocation = ($lenr)"
        
        #Used below     
        $PolicyJSON = Get-CAPolicy -PolicyID $PolicyID 
        $PolicyJSONObject = $PolicyJSON  |  ConvertFrom-Json 



        #Detect Changes
        if($DisplayName -ne [string]::Empty)
        {
            $PolicyJSONObject.displayName = $DisplayName
        } 
        if($State -ne [string]::Empty)
        {
            $PolicyJSONObject.state  = $State
        }

        ##Conditions

        
        ## ConvertFrom-Json / Convertto-Json cannot handle multiple level values correctly PS 5.1
        ## Process Individual complex types seperately
        $conditionsSectionPolicy       = Get-CAPolicySection -SectionName conditions -PolicyJSON $PolicyJSON
        $conditionsSectionPolicy 
        $conditionsSectionPolicyObject = $conditionsSectionPolicy | ConvertFrom-Json 
        
        ##DeviceStates
        ########################################################################################
        if($includeDeviceStates.length -ne 0)
        {
            $conditionsSectionPolicyObject.deviceStates.includeStates= $includeDeviceStates
        }
        if($excludeDeviceStates.length -ne 0)
        {
        $excludeDeviceStates
            $conditionsSectionPolicyObject.deviceStates.excludeStates= $excludeDeviceStates
        }



        ##Locations
        ########################################################################################
        if($includeLocations.length -ne 0)
        {
            $conditionsSectionPolicyObject.locations.includeLocations= $includeLocations
        }
        if($excludeLocations.length -ne 0)
        {
            $conditionsSectionPolicyObject.locations.excludeLocations= $excludeLocations
        }

        ##Times
        ########################################################################################



        ## SignInRiskLevel
        ########################################################################################
        if($signInRiskLevels.length -ne 0)
        {
            $conditionsSectionPolicyObject.signInRiskLevels = $signInRiskLevels
        }


        ## ClientAppsType
        ########################################################################################
        if($ClientAppsTypes.length -ne 0)
        {
           $conditionsSectionPolicyObject.clientAppTypes    = $ClientAppsTypes
        }

        ## Platforms
        ## Future use case on not-configured.
        ########################################################################################

        if($includePlatforms.length -ne 0)
        {
            
            $conditionsSectionPolicyObject.platforms.includePlatforms       = $includePlatforms
                     
        }
        if($excludePlatforms.length -ne 0)
        {
            $conditionsSectionPolicyObject.platforms.excludePlatforms       = $excludePlatforms
            
        }
        
        ##Users
        ########################################################################################
        if($includeUsers.length -ne 0)
        {
           $conditionsSectionPolicyObject.users.includeRoles=  $includeUsers       
        }
        if($excludeUsers.length -ne 0)
        {
            $conditionsSectionPolicyObject.users.excludeUsers = $excludeUsers
        }
        if($includeGroups.length -ne 0)
        {
            $conditionsSectionPolicyObject.users.includeGroups = $includeGroups
        }
        if($excludeGroups.length -ne 0)
        {
            $conditionsSectionPolicyObject.users.excludeGroups = $excludeGroups
        }
        if($includeRoles.length -ne 0)
        {
            $conditionsSectionPolicyObject.users.includeRoles = $includeRoles
        }
        if($excludeRoles.length -ne 0)
        {
            $conditionsSectionPolicyObject.users.excludeRoles = $excludeRoles
        }


        $conditionsSectionPolicyObject 
        $conditionsSectionPolicyObject | ConvertTo-Json | Out-File "c:\temp\set3.json"

 }

 Set-CAPolicy -PolicyID cb015840-1572-4ad2-853a-f2aa3bb648df -DisplayName "Tutor" `
 -excludeLocations none,wastech -includeLocations NALL -includeDeviceStates All  -excludeDeviceStates DomainJoined , Compliant `
 -State Disabled -signInRiskLevels High,Low -ClientAppsTypes Browser,EasUnsupported -includePlatforms Android,ios -excludePlatforms windows `
 -includeUsers "user1" ,"user2" -excludeUsers "user3","user4" -includeGroups "group1", "group2" -excludeGroups "exgroup1","exgroup2" -includeRoles "role1","role2" -excludeRoles "exrol1", "exrole2" 
 


 
 
        
   



        #$PolicyJSON = Get-CAPolicy -PolicyID e2856a3d-a9fd-4202-9fbe-e838dc91bd8c
        #$PolicyJSONObject = $PolicyJSON  |  ConvertFrom-Json 
        #$PolicyJSONObject | ConvertTo-Json | Out-File "c:\temp\set.json"
        #$PolicyJSONObject.conditions.signInRiskLevels ="High","Low"
        #$PolicyJSONObject
        #$PolicyJSONObject | ConvertTo-Json | Out-File "c:\temp\set.json"
        #$PolicyJSONObject.conditions.users.includeUsers


#===============================
#Get-CAPolicy
#New-CAPolicy
Start-CAPolicyBackup -ExportFileName C:\temp\all.json
#Start-CAPolicyRestore
#===============================






#Get-CAPolicy -PolicyID e2856a3d-a9fd-4202-9fbe-e838dc91bd8c
#Start-CAPolicyRestore -PolicyBackupFile C:\temp\g2.json -State Disabled
#Start-CAPolicyBackup -ExportFileName c:\temp\g2.json

#$Abc = Get-ConditionalAccessPolicy  
#$abc.value.grantControls
#$abc.value.grantControls.builtinControls

function Set-ConditionalAccessPolicy{
 Param(
        [string]$PolicyID,
        [ValidateSet("Block","Mfa","CompliantDevice","DomainJoinedDevice","ApprovedApplication","CompliantApplication","FederatedMfa","FederatedCertAuth")][String]$AccessGrantControl,
        [ValidateSet("applicationEnforcedRestrictions","cloudAppSecurity","signInFrequency","persistentBrowser")][String]$SessionControls,
        [ValidateSet("McasConfigured","MonitorOnly","BlockDownloads","ProtectDownloads")][String]$applicationEnforcedRestrictionsSessionControl,
        [ValidateSet("Days","Hours")][String]$signInFrequencySessionControl,
        [ValidateSet("always","never")][String]$persistentBrowserSessionMode,
        [ValidateSet("includeApplications","excludeApplications","includeAuthenticationContext")][String]$AccessApplications,
        [ValidateSet("Browser","Modern","EasSupported","EasUnsupported","Other")][String]$ClientApps,
        [ValidateSet("includeStates","excludeStates")][String]$DeviceStates,
        [ValidateSet("Compliant","DomainJoined")][String]$excludeStates,
        [ValidateSet("All","Android","Ios","Windows","WindowsPhone","MacOs")][String]$AccessPlatforms

        )

}



