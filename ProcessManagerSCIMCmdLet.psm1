param(
    [parameter(Position=0,Mandatory=$false)][string]$g_apikey,
    [parameter(Position=1,Mandatory=$false)][string]$g_url="https://api.promapp.com"
)

function SCIMUser2UserObject {
  Param(
    $response
  )
  process {
    $user = New-Object PSObject
    $user | Add-Member -MemberType NoteProperty -Name "Logon" -Value $response.userName
    $user | Add-Member -MemberType NoteProperty -Name "ID" -Value $response.id
    $user | Add-Member -MemberType NoteProperty -Name "FirstName" -Value $response.name.givenName
    $user | Add-Member -MemberType NoteProperty -Name "LastName" -Value $response.name.familyName
    $user | Add-Member -MemberType NoteProperty -Name "Active" -Value $response.active 
    $user | Add-Member -MemberType NoteProperty -Name "Email" -Value $response.emails[0].value
    $user | Add-Member -MemberType NoteProperty -Name "CreatedAt" -Value $response.meta.created

    $user | Add-Member -MemberType NoteProperty -Name "Roles" -Value @()
    foreach ($role in $response.Roles) {
      $user.Roles += $role.display
    }

    return $user
  }
}

function UserObject2SCIMUser {
  Param(
    [psobject]$UserObject
  )

  process {
    $jsonObj = New-Object PSObject
    $jsonObj | Add-Member -MemberType NoteProperty -Name "userName" -Value $UserObject.Logon
    
    $nameobj = New-Object PSObject
    $nameobj | Add-Member -MemberType NoteProperty -Name "givenName" -Value $UserObject.FirstName
    $nameobj | Add-Member -MemberType NoteProperty -Name "familyName" -Value $UserObject.LastName

    $jsonObj | Add-Member -MemberType NoteProperty -Name "name" -value $nameobj
    $jsonObj | Add-Member -MemberType NoteProperty -Name "active" -Value $UserObject.Active
    $jsonObj | Add-Member -MemberType NoteProperty -Name "emails" -value (New-object System.Collections.Arraylist)
    $emailObj = New-Object psobject
    $emailObj | Add-Member NoteProperty -name "value" -Value $UserObject.Email
    $jsonObj.emails += $emailObj

    $jsonObj | Add-Member -MemberType NoteProperty -Name "roles" -value (New-object System.Collections.Arraylist)
    foreach ($role in $UserObject.Roles) {
      $roleItem = New-Object psobject
      $roleItem | Add-Member NoteProperty -name "display" -Value $role
      $jsonObj.Roles += $roleItem
    }

    return $jsonObj | ConvertTo-Json   
  }

}

function Get-ProcessManagerUser {
    <#
    .SYNOPSIS
    Retrieve a user.

    .DESCRIPTION
    This retrieves a single user (by ID) from your Process Manager tenant. Returns a user object.

    .PARAMETER ID
    The ID of the user.

    .PARAMETER URL
    The URL of the Process Manager API. Should normally not need to change.

    .PARAMETER APIKEY
    The APIKey used to authenticate against the Process Manager SCIM API.

    #>
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory=$False)]  
    [string] $URL = $g_url,
    [Parameter(Mandatory=$False)]
    [string] $APIKEY = $g_apikey,
    [Parameter(Mandatory=$False)]
    [int] $ID,
    [Parameter(Mandatory=$False)]
    [string] $Logon
  )
  
  process {
    if ([string]::IsNullOrEmpty($APIKEY) -eq $True) {
      Write-Error "APIKEY must be provided"
      return
    }
    if ($ID -ne 0) {
      $tmpurl = "${URL}/api/scim/users/${ID}"
      $user = Invoke-RestMethod -Headers @{"Authorization" = "Bearer ${APIKEY}"} -Method GET  -Uri $tmpurl
      $obj = SCIMUser2UserObject -response $user
      return $obj
    } elseif ([string]::IsNullOrEmpty($Logon) -eq $False) {
      $tmpurl = "${URL}/api/scim/users?filter=userName eq ""${Logon}"""
      $response = Invoke-RestMethod -Headers @{"Authorization" = "Bearer ${APIKEY}"} -Method GET  -Uri $tmpurl
      if ($response.totalResults -eq 0) {
        Write-Error "Could not find user with that Logon"
        return
      }
      $obj = SCIMUser2UserObject -response $response.Resources[0]
      return $obj

    } else {
      Write-Error "Need to provide at least ID or Logon"
    }
  }
}   

function Get-ProcessManagerUsers {
    <#
    .SYNOPSIS
    Retrieve all users.

    .DESCRIPTION
    This retrieves all users from your Process Manager tenant and returns them as an array of user objects.
    
    .PARAMETER URL
    The URL of the Process Manager API. Should normally not need to change.

    .PARAMETER APIKEY
    The APIKey used to authenticate against the Process Manager SCIM API.

    #>
  [CmdletBinding()]
    Param(
      [Parameter(Mandatory=$False)]  
      [string] $URL = $g_url,
      [Parameter(Mandatory=$False)]
      [string] $APIKEY = $g_apikey
    )
    
    process {
      if ([string]::IsNullOrEmpty($APIKEY) -eq $True) {
        Write-Error "APIKEY must be provided"
        return
      }

      
      $start = 0
      $allusers = @()

      while (1) {
        $tmpurl = "${URL}/api/scim/Users?startIndex=${start}"
        try { 
          # tried https://stackoverflow.com/a/75345304 but that didn't work, so using the more-upvoted try/catch
          $response = Invoke-RestMethod -Headers @{"Authorization" = "Bearer ${APIKEY}"} -Method GET  -Uri $tmpurl
        }
        catch {
          Write-Host "Failed to retrieve users: " $_.Exception
          Write-Host "HTTP Status code: " $_.Exception.Response.StatusCode.value__ 
          return
        }

        foreach ($res in $response.Resources) {
          $allusers += SCIMUser2UserObject $res
        }

        if ($response.totalResults -lt $response.itemsPerPage) {
          break
        }

        $start += $response.itemsPerPage
      }
      return $allusers
    }
}   

function New-ProcessManagerUser {
     <#
    .SYNOPSIS
    Create a new user.

    .DESCRIPTION
    Allows you to create a user withing Process Manager. Two parameter options can be provided. Either a user object or individual parameters.
    
    .PARAMETER Logon
    The username of the User.
  
    .PARAMETER FirstName
    The firstname of the user.

    .PARAMETER LastName
    The lastname of the user.

    .PARAMETER Active
    Set the user active or not. (default true)

    .PARAMETER Email
    The email address of the user.

    .PARAMETER Roles
    Array of strings, which indicate which roles the user should belong to.
    
   .PARAMETER user
    An object (retrieved by Get-ProcessManagerUser) with the update information of the user.

    .PARAMETER URL
    The URL of the Process Manager API. Should normally not need to change.

    .PARAMETER APIKEY
    The APIKey used to authenticate against the Process Manager SCIM API.

    #>
  [CmdletBinding(DefaultParameterSetName="Properties")]
  param (
    [Parameter(Mandatory=$false)]  
    [string] $URL = $g_url,
    [Parameter(Mandatory=$false)]
    [string] $APIKEY = $g_apikey,
  
    [Parameter(ParameterSetName="UserObject", Mandatory=$true)]
    [psobject]$user,
    
    [Parameter(ParameterSetName="Properties", Mandatory=$true)]
    [string]$Logon,

    [Parameter(ParameterSetName="Properties", Mandatory=$true)]
    [string]$FirstName,
    
    [Parameter(ParameterSetName="Properties", Mandatory=$true)]
    [string]$LastName,

    [Parameter(ParameterSetName="Properties", Mandatory=$false)]
    [bool]$Active = $true,

    [Parameter(ParameterSetName="Properties", Mandatory=$true)]
    [string]$Email,

    [Parameter(ParameterSetName="Properties", Mandatory=$false)]
    [string[]]$Roles
  )

  process {
    if ([string]::IsNullOrEmpty($APIKEY) -eq $True) {
      Write-Error "APIKEY must be provided"
      return
    }

    if ($PSCmdlet.ParameterSetName -eq "Properties") {
      $user = New-Object psobject
      $user | Add-Member -MemberType NoteProperty -Name "Logon" -Value $Logon
      $user | Add-Member -MemberType NoteProperty -Name "FirstName" -Value $FirstName
      $user | Add-Member -MemberType NoteProperty -Name "LastName" -Value $LastName
      $user | Add-Member -MemberType NoteProperty -Name "Active" -Value $Active
      $user | Add-Member -MemberType NoteProperty -Name "Email" -Value $Email
      $user | Add-Member -MemberType NoteProperty -Name "Roles" -value $Roles
    }

    $postJson = UserObject2SCIMUser $user
    $tmpurl = "${URL}/api/scim/Users"

    $res = Invoke-RestMethod -Headers @{"Authorization" = "Bearer ${APIKEY}"} -Method POST -Uri $tmpurl  -Body $postJson -ContentType "application/scim+json"
    return SCIMUser2UserObject -response $res
  }
}

function Update-ProcessManagerUser {
   <#
    .SYNOPSIS
    Update a user.

    .DESCRIPTION
    Allows you to update a user withing Process Manager. Two parameter options can be provided. Either a user object (retrieved with Get-ProcessManagerUser) or a user ID and a parameter for what you want to update.
    If the user object is supplied, then the request is made directly. If the ID is provided, then the user is retrieved, updated with the other values supplied and then updated in Process Manager.

    .PARAMETER ID
    The ID of the user to update.
    
    .PARAMETER Logon
    The username of the User.
  
    .PARAMETER FirstName
    The firstname of the user.

    .PARAMETER LastName
    The lastname of the user.

    .PARAMETER Active
    Set the user active or not.

    .PARAMETER Email
    The email address of the user.

    .PARAMETER Roles
    Array of strings, which indicate which roles the user should belong to.
    
   .PARAMETER user
    An object (retrieved by Get-ProcessManagerUser) with the update information of the user.

    .PARAMETER URL
    The URL of the Process Manager API. Should normally not need to change.

    .PARAMETER APIKEY
    The APIKey used to authenticate against the Process Manager SCIM API.
    #>


  [CmdletBinding(DefaultParameterSetName="UserObject")]
  param (
    [Parameter(Mandatory=$false)]  
    [string] $URL = $g_url,
    [Parameter(Mandatory=$false)]
    [string] $APIKEY = $g_apikey,
  
    [Parameter(ParameterSetName="UserObject", Mandatory=$true)]
    [psobject]$user,

    [Parameter(ParameterSetName="Properties", Mandatory=$true)]
    [int]$ID,

    [Parameter(ParameterSetName="Properties", Mandatory=$false)]
    [string]$Logon,

    [Parameter(ParameterSetName="Properties", Mandatory=$false)]
    [string]$FirstName,
    
    [Parameter(ParameterSetName="Properties", Mandatory=$false)]
    [string]$LastName,

    [Parameter(ParameterSetName="Properties", Mandatory=$false)]
    [ValidateSet($null, $true, $false)]
    [object] $Active,

    [Parameter(ParameterSetName="Properties", Mandatory=$false)]
    [string]$Email,

    [Parameter(ParameterSetName="Properties", Mandatory=$false)]
    [string[]]$Roles

  )

  process {
    if ([string]::IsNullOrEmpty($APIKEY) -eq $True) {
      Write-Error "APIKEY must be provided"
      return
    }

    if ($PSCmdlet.ParameterSetName -eq "Properties") {
      $user = Get-ProcessManagerUser -URL $URL -APIKEY $APIKEY -ID $ID
      if ([string]::IsNullOrEmpty($Logon) -eq $false) {
        $user.Logon = $Logon
      }
      if ([string]::IsNullOrEmpty($FirstName) -eq $false) {
        $user.FirstName = $FirstName
      }
      if ([string]::IsNullOrEmpty($LastName) -eq $false) {
        $user.LastName = $LastName
      }
      if ($Active -ne $null) {
        $user.Active = $Active
      }
      if ([string]::IsNullOrEmpty($Email) -eq $false) {
        $user.Email = $Email
      }
      if ($Roles.Length -gt 0) {
        $user.Roles = $Roles
      } 
    }

    $postJson = UserObject2SCIMUser -UserObject $user
    $tmpurl = "$($URL)/api/scim/Users/$($user.ID)"
    $res = Invoke-RestMethod -Headers @{"Authorization" = "Bearer ${APIKEY}"} -Method PUT -Uri $tmpurl -Body $postJson -ContentType "application/scim+json"
    return SCIMUser2UserObject -response $res
  }
}

function Disable-ProcessManagerUser {
   <#
    .SYNOPSIS
    Disable a user

    .DESCRIPTION
    This allows you to disable the user. It is a shorthand for Get-ProcessManagerUser and changing the Active to false property and performing Update-ProcessManagerUser.

    .PARAMETER ID
    The ID of the user.

    .PARAMETER URL
    The URL of the Process Manager API. Should normally not need to change.

    .PARAMETER APIKEY
    The APIKey used to authenticate against the Process Manager SCIM API.

    .EXAMPLE
    Disable-ProcessManagerUser -ID 20
    Disable the user with ID 20.

    #>
    [CmdletBinding()]
  param (
    [Parameter(Mandatory=$false)]  
    [string] $URL = $g_url,
    [Parameter(Mandatory=$false)]
    [string] $APIKEY = $g_apikey,
  
    [Parameter(Mandatory=$true)]
    [int]$ID
  )

  process {
    if ([string]::IsNullOrEmpty($APIKEY) -eq $True) {
      Write-Error "APIKEY must be provided"
      return
    }

    $user = Get-ProcessManagerUser -URL $URL -APIKEY $APIKEY -ID $ID
    $user.Active = $false
    Update-ProcessManagerUser -URL $URL -APIKEY $APIKEY -user $user
  }
}

function Enable-ProcessManagerUser {
    <#
    .SYNOPSIS
    Enable a user

    .DESCRIPTION
    This allows you to enable the user. It is a shorthand for Get-ProcessManagerUser and changing the Active to true property and performing Update-ProcessManagerUser.

    .PARAMETER ID
    The ID of the user. Should be retrieved with Get-ProcessManagerUsers.

    .PARAMETER URL
    The URL of the Process Manager API. Should normally not need to change.

    .PARAMETER APIKEY
    The APIKey used to authenticate against the Process Manager SCIM API.

    .EXAMPLE
    Enable-ProcessManagerUser -ID 20
    Enable the user with ID 20.

    #>
  [CmdletBinding()]
  param (
    [Parameter(Mandatory=$false)]  
    [string] $URL = $g_url,
    [Parameter(Mandatory=$false)]
    [string] $APIKEY = $g_apikey,
  
    [Parameter(Mandatory=$true)]
    [int]$ID
  )

  process {
    if ([string]::IsNullOrEmpty($APIKEY) -eq $True) {
      Write-Error "APIKEY must be provided"
      return
    }

    $user = Get-ProcessManagerUser -URL $URL -APIKEY $APIKEY -ID $ID
    $user.Active = $true
    Update-ProcessManagerUser -URL $URL -APIKEY $APIKEY -user $user
  }
}

Export-ModuleMember -Function Get-ProcessManagerUsers
Export-ModuleMember -Function Get-ProcessManagerUser
Export-ModuleMember -Function New-ProcessManagerUser
Export-ModuleMember -Function Update-ProcessManagerUser
Export-ModuleMember -Function Disable-ProcessManagerUser
Export-ModuleMember -Function Enable-ProcessManagerUser 