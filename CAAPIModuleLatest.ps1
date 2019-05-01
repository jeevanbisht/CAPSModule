$tenantDomain = 'identt.work' #change your tenant domain
$clientID = 'd9952f13-0ebe-468b-a44e-ba7e99bebcf0'  #change to your AppID

Import-Module MSCloudIdUtils
#$accessToken = Get-MSCloudIdAccessTokenFromUser -TenantDomain $tenantDomain -ClientId $clientID -Resource 'https://canary.graph.microsoft.com' -RedirectUri 'urn:ietf:wg:oauth:2.0:oob' 

$authHeaders = New-Object 'System.Collections.Generic.Dictionary[[String],[String]]'
$authHeaders.Add('Authorization', 'Bearer ' + $accessToken)
$authHeaders.Add('Content-Type','application/json')
$authHeaders.Add('Accept','application/json, text/plain')
$baseURI = 'https://canary.graph.microsoft.com/testidentityprotectionservices/conditionalaccesspolicies/'




 function New-CAPolicy
{
    ###########################################################################################
    # New-CAPolicy will create a new Policy and if sucessful return the Policy as JSONString
    #
    #
    ###########################################################################################
        Param(
            [Parameter(mandatory=$true)]
            [string]$DisplayName,
            [ValidateSet("Enabled","Disabled")][String]$State,
            [ValidateSet("High","Medium","Low","None")][String[]]$signInRiskLevels,
            [ValidateSet("Browser","Modern","EasSupported","EasUnsupported","None")][String[]]$clientAppTypes,
            [ValidateSet("All","Android","Ios","Windows","WindowsPhone","MacOs")][String[]]$includePlatforms,
            [ValidateSet("All","Android","Ios","Windows","WindowsPhone","MacOs")][String[]]$excludePlatforms,
            [String[]]$includeApplications,
            [String[]]$excludeApplications,
            [String[]]$includeLocations,
            [String[]]$excludeLocations,
            [ValidateSet("All")][String[]]$includeDeviceStates,
            [ValidateSet("Compliant","DomainJoined")][String[]]$excludeDeviceStates,
            [String[]]$includeUsers,
            [String[]]$excludeUsers,
            [String[]]$includeGroups,
            [String[]]$excludeGroups,
            [String[]]$includeRoles,
            [String[]]$excludeRoles,
            [Parameter(mandatory=$true)]
            [ValidateSet("Block","Mfa","CompliantDevice","DomainJoinedDevice","ApprovedApplication","CompliantApplication","FederatedMfa","FederatedCertAuth")][String[]]$accessGrantControls,
            [ValidateSet("AND","OR")][String]$accessGrantControlOperator,
            [String[]]$customControls

        )
                
        $PolicyObject  = New-Object -TypeName PSObject
        $PolicyObject  | Add-Member -MemberType NoteProperty -Name "displayName" -Value $DisplayName
        $PolicyObject  | Add-Member -MemberType NoteProperty -Name "state" -Value  $State

        ###############################################
        ## Conditions Object
        ###############################################
            ## SignInRiskLevel
            if($signInRiskLevels.Length -le 0) { $signInRiskLevels = @() }

            ## ClientAppTypes
            if($clientAppTypes.Length -le 0) { $clientAppTypes = @() }
            

            ## Applications
            $applicationsObject = New-Object -TypeName PSObject
            if($includeApplications.Length -le 0) { $includeApplications = @() }
            $applicationsObject | Add-Member -MemberType NoteProperty -Name "includeApplications" -Value $includeApplications
            if($excludeApplications.Length -le 0) { $excludeApplications = @() }
            $applicationsObject | Add-Member -MemberType NoteProperty -Name "excludeApplications" -Value $excludeApplications
            $applicationsObject | Add-Member -MemberType NoteProperty -Name "includeAuthenticationContext" -Value @()


            ## Platforms
            $platformsObject = $null
            if($includePlatforms.Length -gt 0)
            {
                $platformsObject = New-Object -TypeName PSObject
                $platformsObject | Add-Member -MemberType NoteProperty -Name "includePlatforms" -Value $includePlatforms
                if($excludePlatforms.Length -le 0) { $excludePlatforms = @() }
                $platformsObject | Add-Member -MemberType NoteProperty -Name "excludePlatforms" -Value $excludePlatforms
            }

            ## Locations
            $locationsObject  = $null
            if($includeLocations.Length -gt 0) { 
                $locationsObject = New-Object -TypeName PSObject
                $locationsObject | Add-Member -MemberType NoteProperty -Name "includeLocations" -Value $includeLocations
                if($excludeLocations.Length -le 0) { $excludeLocations = @() }
                $locationsObject | Add-Member -MemberType NoteProperty -Name "excludeLocations" -Value $excludeLocations
            }
            

            ## DeviceState
            $deviceStatesObject = $null
            if($includeDeviceStates.Length -gt 0) { 
                $deviceStatesObject = New-Object -TypeName PSObject
                $deviceStatesObject | Add-Member -MemberType NoteProperty -Name "includeStates" -Value $includeDeviceStates
                if($excludeDeviceStates.Length -le 0) { $excludeDeviceStates = @() }
                $deviceStatesObject | Add-Member -MemberType NoteProperty -Name "excludeStates" -Value $excludeDeviceStates
            }

            ## Users
            $usersObject = New-Object -TypeName PSObject
            if(($includeUsers.Length -le 0)  -and ($includeGroups.Length -le 0)-and ($includeRoles.Length -le 0))
            { $includeUsers ='none' }
            elseif ($includeUsers.Length -le 0)
            { $includeUsers =@() }
            $usersObject | Add-Member -MemberType NoteProperty -Name "includeUsers"  -Value $includeUsers
            if($excludeUsers.Length -le 0) { $excludeUsers = @() }
            $usersObject | Add-Member -MemberType NoteProperty -Name "excludeUsers"  -Value $excludeUsers
            if($includeGroups.Length -le 0) { $includeGroups = @() }
            $usersObject | Add-Member -MemberType NoteProperty -Name "includeGroups" -Value $includeGroups
            if($excludeGroups.Length -le 0) { $excludeGroups = @() }
            $usersObject | Add-Member -MemberType NoteProperty -Name "excludeGroups" -Value $excludeGroups
            if($includeRoles.Length -le 0) { $includeRoles = @() }
            $usersObject | Add-Member -MemberType NoteProperty -Name "includeRoles"  -Value $includeRoles
            if($excludeRoles.Length -le 0) { $excludeRoles = @() }
            $usersObject | Add-Member -MemberType NoteProperty -Name "excludeRoles"  -Value $excludeRoles
        

        
        $conditionsObject  = New-Object -TypeName PSObject
        $conditionsObject | Add-Member -MemberType NoteProperty -Name "signInRiskLevels" -Value $signInRiskLevels
        $conditionsObject | Add-Member -MemberType NoteProperty -Name "clientAppTypes"   -Value $clientAppTypes
        $conditionsObject | Add-Member -MemberType NoteProperty -Name "applications"     -Value $applicationsObject
        $conditionsObject | Add-Member -MemberType NoteProperty -Name "locations"        -Value $locationsObject
        $conditionsObject | Add-Member -MemberType NoteProperty -Name "platforms"        -Value $platformsObject
        $conditionsObject | Add-Member -MemberType NoteProperty -Name "deviceStates"     -Value $deviceStatesObject
        $conditionsObject | Add-Member -MemberType NoteProperty -Name "users"            -Value $usersObject
               
               
        ##Time in Preview ( Skip for this Preview)
        $conditionsObject  | Add-Member -MemberType NoteProperty -Name "times" -Value $null

        ###############################################
        ## Grant Controls
        ###############################################     
        $grantControlsObject = New-Object -TypeName PSObject
        ## Default to OR
        if ($accessGrantControlOperator.Length -le 0) { $accessGrantControlOperator="OR" }
        $grantControlsObject | Add-Member -MemberType NoteProperty -Name "operator"        -Value $accessGrantControlOperator
        $grantControlsObject | Add-Member -MemberType NoteProperty -Name "builtInControls" -Value $accessGrantControls

        if ($customControls.Length -le 0) { $customControls= @() }
        $grantControlsObject | Add-Member -MemberType NoteProperty -Name "customControls"  -Value $customControls

        ###############################################
        ## Session Control
        ###############################################   
        ## Not Implementeda

        ###############################################
        # Create Policy from Sections
        ###############################################
        $PolicyObject | Add-Member -MemberType NoteProperty -Name "conditions"      -Value $conditionsObject
        $PolicyObject | Add-Member -MemberType NoteProperty -Name "grantControls"   -Value $grantControlsObject
        $PolicyObject | Add-Member -MemberType NoteProperty -Name "sessionControls" -Value $null
        
        ###############################################
        # perform POST operation 
        ###############################################
        $PolicyJSONString = $PolicyObject | ConvertTo-Json -Depth 10
        $PolicyURI  = $baseURI
        $responseCA =  try { Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $PolicyURI -Method Post -Body $PolicyJSONString } catch { $_.Exception.Response}
        
        Write-Host $responseCA.statuscode

         
                       
  return $responseCA
        

        

 }

 $Policy= New-CAPolicy -DisplayName "NewPolicyA21" -State Disabled -accessGrantControls DomainJoinedDevice,Mfa  -includeApplications 00000002-0000-0ff1-ce00-000000000000  -includeDeviceStates All -excludeDeviceStates Compliant,DomainJoined #-includeLocations "All"  # -excludeUsers  "4f38e772-6db9-42cd-943b-28db2be17dec" -
 
 


