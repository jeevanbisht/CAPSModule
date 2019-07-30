
$tenantDomain = 'consoto.com' #change your tenant domain
$clientID = '95c29d23-ad47-4608-845e-4e370418ef05'  #change to your AppID

Import-Module MSCloudIdUtils

$accessToken = Get-MSCloudIdAccessTokenFromUser -TenantDomain $tenantDomain -ClientId $clientID -Resource 'https://canary.graph.microsoft.com' -RedirectUri 'urn:ietf:wg:oauth:2.0:oob' 
$authHeaders = New-Object 'System.Collections.Generic.Dictionary[[String],[String]]'
$authHeaders.Add('Authorization', 'Bearer ' + $accessToken)
$authHeaders.Add('Content-Type','application/json')
$authHeaders.Add('Accept','application/json, text/plain')
$baseURI = 'https://canary.graph.microsoft.com/testidentityprotectionservices/conditionalaccesspolicies'


function New-CAPolicy{
    ###########################################################################################
    # New-CAPolicy will create a new Policy and if sucessful return the Policy as JSONString
    # Returns 
    #  StatusCode  ::  if failed Contain HTTP ( 201 Success )
    #  Content     ::  JSON Object if sucessfull
    ###########################################################################################
        Param(
            [Parameter(mandatory=$true)]
            [string]$DisplayName,
            [Parameter(mandatory=$true)]
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
            [ValidateSet("Block","Mfa","CompliantDevice","DomainJoinedDevice","ApprovedApplication","CompliantApplication","FederatedMfa","FederatedCertAuth")][String[]]$accessGrantControls,
            [ValidateSet("AND","OR")][String]$accessGrantControlOperator,
            [String[]]$customAuthenticationFactors

        )
                
        $PolicyObject  = New-Object -TypeName PSObject
        $PolicyObject  | Add-Member -MemberType NoteProperty -Name "displayName" -Value $DisplayName
        $PolicyObject  | Add-Member -MemberType NoteProperty -Name "state" -Value  $State

        
        ## Conditions Object
        #------------------------------------------------------------------------
            ## SignInRiskLevel
            if($signInRiskLevels.Length -le 0) { $signInRiskLevels = @() }

            ## ClientAppTypes
            if($clientAppTypes.Length -le 0) { $clientAppTypes = @() }
            

            ## Applications
            #------------------------------------------------------------------------
            $applicationsObject = New-Object -TypeName PSObject
            if(($includeApplications.Length -le 0)  -and ($excludeApplications.Length -le 0))
            { $includeApplications ='none' }
            elseif ($includeApplications.Length -le 0)
            { $includeApplications =@() }
            $applicationsObject | Add-Member -MemberType NoteProperty -Name "includeApplications" -Value $includeApplications
            if($excludeApplications.Length -le 0) { $excludeApplications = @() }
            $applicationsObject | Add-Member -MemberType NoteProperty -Name "excludeApplications" -Value $excludeApplications
            $applicationsObject | Add-Member -MemberType NoteProperty -Name "includeAuthenticationContext" -Value @()


            ## Platforms
            #------------------------------------------------------------------------
            $platformsObject = $null
            if($includePlatforms.Length -gt 0)
            {
                $platformsObject = New-Object -TypeName PSObject
                $platformsObject | Add-Member -MemberType NoteProperty -Name "includePlatforms" -Value $includePlatforms
                if($excludePlatforms.Length -le 0) { $excludePlatforms = @() }
                $platformsObject | Add-Member -MemberType NoteProperty -Name "excludePlatforms" -Value $excludePlatforms
            }

            ## Locations
            #------------------------------------------------------------------------
            $locationsObject  = $null
            if($includeLocations.Length -gt 0) { 
                $locationsObject = New-Object -TypeName PSObject
                $locationsObject | Add-Member -MemberType NoteProperty -Name "includeLocations" -Value $includeLocations
                if($excludeLocations.Length -le 0) { $excludeLocations = @() }
                $locationsObject | Add-Member -MemberType NoteProperty -Name "excludeLocations" -Value $excludeLocations
            }
            

            ## DeviceState
            #------------------------------------------------------------------------
            $deviceStatesObject = $null
            if($includeDeviceStates.Length -gt 0) { 
                $deviceStatesObject = New-Object -TypeName PSObject
                $deviceStatesObject | Add-Member -MemberType NoteProperty -Name "includeStates" -Value $includeDeviceStates
                if($excludeDeviceStates.Length -le 0) { $excludeDeviceStates = @() }
                $deviceStatesObject | Add-Member -MemberType NoteProperty -Name "excludeStates" -Value $excludeDeviceStates
            }

            ## Users
            #------------------------------------------------------------------------
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

        
        ## Grant Controls
        #------------------------------------------------------------------------     
        $grantControlsObject = New-Object -TypeName PSObject
        ## Default to OR
        if ($accessGrantControlOperator.Length -le 0) { $accessGrantControlOperator="OR" }
        $grantControlsObject | Add-Member -MemberType NoteProperty -Name "operator"        -Value $accessGrantControlOperator
        if ($accessGrantControls.Length -le 0) { $accessGrantControls="mfa" }
        $grantControlsObject | Add-Member -MemberType NoteProperty -Name "builtInControls" -Value $accessGrantControls

        if ($customAuthenticationFactors.Length -le 0) { $customAuthenticationFactors= @() }
        $grantControlsObject | Add-Member -MemberType NoteProperty -Name "customAuthenticationFactors"  -Value $customAuthenticationFactors

        
        ## Session Control
        #------------------------------------------------------------------------
        ## Not Implementeda

        
        # Create Policy from Sections
        #------------------------------------------------------------------------
        $PolicyObject | Add-Member -MemberType NoteProperty -Name "conditions"      -Value $conditionsObject
        $PolicyObject | Add-Member -MemberType NoteProperty -Name "grantControls"   -Value $grantControlsObject
        $PolicyObject | Add-Member -MemberType NoteProperty -Name "sessionControls" -Value $null
        
        ###############################################
        # perform POST operation 
        ###############################################
        $PolicyJSONString = $PolicyObject | ConvertTo-Json -Depth 10
        $PolicyURI  = $baseURI
        $responseCA =  try { Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $PolicyURI -Method Post -Body $PolicyJSONString } catch { $_.Exception.Response}
        


        $result = $null
        if ($responseCA.StatusCode -eq "201")
        {
            $PolicyJSON       = ConvertFrom-Json $responseCA.Content
            $PolicyJSONObject = $PolicyJSON | ConvertTo-Json -Depth 10 -Compress
            $result=$PolicyJSON

            
        }
        else
        {
            $result= $responseCA.StatusCode
        }
        
    return $result
        

 }

function Start-CAPolicyBackup{
    ###########################################################################################
    # Start-CAPolicyBackup will export all Policies
    # Returns the Policies as JSON part of the HTTP Response in the Content Field
    # StatusCode  ::  200 - Success
    # Content     ::  Contains the actual Policy if creation was sucessful
    ###########################################################################################
        Param(
             [Parameter(mandatory=$true)]
             [string]$BackupFileName
        )

    $PolicyURI  = $baseURI
    $PolicyJSON = $null

    $responseCA =  try { Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $PolicyURI -Method Get } catch { $_.Exception.Response}
    if($responseCA.StatusCode -eq "200")
    {
        
        $PolicyJSON = ConvertFrom-Json $responseCA.Content
        $PolicyJSON | ConvertTo-Json -Depth 10  | Out-File $BackupFileName 
    
    }
 return $responseCA.StatusCode
  
}

function Start-CAPolicyRestore{
    ###########################################################################################
    # Start-CAPolicyBackup will export all Policies
    # This is a POST opeartion 
    # Returns Custom Object Indicating Status for every policy restoration.
    ###########################################################################################
    Param(
        [Parameter(mandatory=$true)]
        [string]$PolicyBackupFile,                
        [ValidateSet("Enabled","Disabled")][String]$State 
    )
 
        $PolicyRestoreList =  [System.Collections.ArrayList]@()       
        
        if ($State.Length -eq 0) { $State ="Disabled" }   
        $PolicyJSON = Get-Content -Path $PolicyBackupFile -Raw | ConvertFrom-Json 
 
        foreach( $PolicyJSONObject  in $PolicyJSON.value)
        {
    
            
            # Remove fields that cannot be restored
            #------------------------------------------------------------------------
            $tempID=$PolicyJSONObject.id
            $PolicyJSONObject.PSObject.Properties.Remove('id')
            $PolicyJSONObject.PSObject.Properties.Remove('createdDateTime')
            $PolicyJSONObject.PSObject.Properties.Remove('modifiedDateTime')
            $RestoredDisplayName=($PolicyJSONObject.displayName.ToString() + " (Restored from Backup)")
            $PolicyJSONObject.displayName=$RestoredDisplayName
            $PolicyJSONObject.state = $State
            $PolicyJSONObjectString = $PolicyJSONObject  | ConvertTo-Json -depth 20  -Compress

            
            
            # perform POST operation 
            #------------------------------------------------------------------------
            $PolicyURI  = $baseURI
            $responseCA =  try { Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $PolicyURI -Method Post -Body $PolicyJSONObjectString } catch { $_.Exception.Response}
            
           
            
            # Capture Detail of each Restore Operation
            #------------------------------------------------------------------------
            $PolicyRestoreObject = New-Object -TypeName PSObject
            $PolicyRestoreObject | Add-Member -MemberType NoteProperty -Name "Id"            -Value  $tempID
            $PolicyRestoreObject | Add-Member -MemberType NoteProperty -Name "DisplayName"   -Value  $PolicyJSONObject.displayName
            $PolicyRestoreObject | Add-Member -MemberType NoteProperty -Name "HTTP Response" -Value  $responseCA.StatusCode
            $PolicyRestoreList.Add($PolicyRestoreObject)
            
         }
                                                                    
 return $PolicyRestoreList   
}

function Get-CAPolicy {
    ###########################################################################################
    # Get-CAPolicy resturns the collection of Polcies matching conditions
    # This is GET operations
    # 
    ###########################################################################################

    Param(
        [ValidateSet("PolicyID","PolicyName")][String[]]$Type,
        [Parameter(mandatory=$true)]
        [string]$Id
    )
 
     
    $result = $null
    
    # Lookup by Policy ID
    #------------------------------------------------------------------------
    if (  ($Id.Length -gt 0) -and ($Type -ne "PolicyName") )
    {

        ###############################################
        # perform GET operation 
        ###############################################
        $PolicyId         = $Id
        $PolicyURI        = $baseURI + "/" + $PolicyId

        $Response         = try { Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $PolicyURI -Method GET } catch { $_.Exception.Response}
        $PolicyJSON       = ConvertFrom-Json $Response.Content
        $PolicyJSONObject = $PolicyJSON | ConvertTo-Json -Depth 10 -Compress
        $result=$PolicyJSON
     
    } 

    
    # Lookup by Policy Name
    #------------------------------------------------------------------------
    if (  ($Id.Length -gt 0) -and ($Type -eq "PolicyName") )
    {

        
        # GET All Policies
        #------------------------------------------------------------------------
        $PolicyURI        = $baseURI 
        $Response        = try { Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $PolicyURI -Method GET } catch { $_.Exception.Response}
        $PoliciesText    = Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $PolicyURI -Method Get
        $PolicyObectList = [System.Collections.ArrayList]@();
        $policiesJSONObject  = ConvertFrom-Json $PoliciesText

             foreach($PolicyJSONObj in $policiesJSONObject.value)
            {

                [string]$PolicyDispName= $PolicyJSONObj.displayName
                if ($PolicyDispName.ToLower() -eq $id.ToLower())
                {
                  
                  $retrunCode=$PolicyObectList.Add($PolicyJSONObj) 
                }
           }
        $result=$PolicyObectList
    }

 return $result
}

Function Remove-CAPolicy{
    [cmdletbinding()]
    [Parameter(mandatory=$true)]
    Param (
        [parameter(ValueFromPipelineByPropertyName=$True)]
        [String]$Id
    )

     ###############################################
     # perform DELETE operation 
     ###############################################
     $PolicyURI  = $baseURI + "/"+ $Id
     #write-host $PolicyURI
     $responseCA =  try { Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $PolicyURI -Method DELETE  } catch { $_.Exception.Response}
     return $responseCA
}

function Set-CAPolicy {
[cmdletbinding()]
    Param (
        [parameter(Mandatory=$true,ValueFromPipeLine=$true)]
        [PSObject]$Id
        
    )
          
      $result = $null
      $InputObject   = $null
      $samplePolicyIDGuid="128535ce-cafd-44cd-9ee2-ab12c8137cb1"
      
      if($Id.Length -eq  $samplePolicyIDGuid.Length)
      {
        # Policy ID Specified
        #------------------------------------------------------------
        $policyItem= Get-CAPolicy -Id $Id -Type PolicyID 
        $InputObject= $policyItem | ConvertTo-Json -Depth 50 
       
      }
      else 
      {
        
        # Policy Object in PipeLine
        #------------------------------------------------------------
        $InputObject = $Id | ConvertTo-Json -Depth 50 
      }

                
        # Create Policy Object
        #------------------------------------------------------------
        $PolicyJSONObject       = $InputObject | ConvertFrom-Json
        $PolicyJSONObjectString = $PolicyJSONObject | ConvertTo-Json -Depth 50 -Compress
        $PolicyURI              = $baseURI + "/" + $PolicyJSONObject.id
        
        
            ###############################################
            # perform PATCH Operation 
            ###############################################
            $responseCA    = try { Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $PolicyURI -Method PATCH -Body $PolicyJSONObjectString } catch { $_.Exception.Response}
            $result = $responseCA
            #$PolicyJSONObject | ConvertTo-Json -Depth 50  | Out-File C:\temp\set.json

      
return $result
          
   

}

<#
 .Synopsis
  Displays a visual representation of a calendar.
#>
Export-ModuleMember -Function New-CAPolicy
Export-ModuleMember -Function Start-CAPolicyBackup
Export-ModuleMember -Function Start-CAPolicyRestore
Export-ModuleMember -Function Get-CAPolicy
Export-ModuleMember -Function Set-CAPolicy
