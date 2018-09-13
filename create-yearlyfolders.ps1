#requires -version 3
<#
.SYNOPSIS
  Creates yearly user folders

.DESCRIPTION
  Creates folders in each users personal drive for the year, also includes several subfolders as requested

.PARAMETER $year
  The year to create

.INPUTS
  None

.OUTPUTS Log File
  The script log file stored in C:\TSC\Scripts\Logs\YearlyFolder YY-MM-DD.log

.NOTES
  Version:        1.5
  Author:         James McGeorge
  Creation Date:  28/12/2015
  Purpose/Change: Initial script development

.EXAMPLE
  .\Create-YearlyFolders.ps1 -year 2014

  This will create user folders in each users Y: drive with the root being 2014
#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

#Set Error Action to Silently Continue
$ErrorActionPreference = 'SilentlyContinue'

#Import PSLogging Module
Import-Module PSLogging

#----------------------------------------------------------[Declarations]----------------------------------------------------------

#Script Version
$sScriptVersion = '1.0'

#Log File Info
$sLogPath = 'C:\TSC\Scripts\Logs'
$date = Get-Date -format yy.M.d
$sLogName = 'YearlyFolder' + $date + '.log'
$sLogFile = Join-Path -Path $sLogPath -ChildPath $sLogName

#-----------------------------------------------------------[Functions]------------------------------------------------------------



Function Create-YearlyFolders {
  Param (
    [Parameter(Mandatory=$true,Position=1)]
    [string]$year
  )

  Begin {
    Import-Module Activedirectory
    Start-Log -LogPath $sLogPath -LogName $sLogName -ScriptVersion $sScriptVersion
    Write-LogInfo -LogPath $sLogFile -Message 'Beginning creation of Yearly Folders'
  }

  Process {
    Try {
        $userfolders = Get-ChildItem \\FS1\Users
        foreach ($folder in $userfolders){
            $path = $folder.FullName + "\" + $year
            if (-not (Test-Path $path)){
                New-Item -ItemType directory -Path $path
                Write-LogInfo -LogPath $sLogFile -Message "$($path) created."
            } else {
                Write-LogInfo -LogPath $sLogFile -Message "$($path) already exists, skipping creation."
            }
            $folderlist = Get-Content C:\TSC\Scripts\SubFolders.txt
            foreach ($entry in $folderlist){
                $subfolder = $path + "\" + $entry
                if (-not (Test-Path $subfolder)){
                    New-Item -ItemType directory -Path $subfolder
                    Write-LogInfo -LogPath $sLogFile -Message "$($subfolder) created."
                } else {
                    Write-LogInfo -LogPath $sLogFile -Message "$($subfolder) already exists, skipping creation."
                }
            }

            Write-LogInfo -LogPath $sLogFile -Message "Setting Permissions..."

            $user = "DOMAIN\" + $folder.Name
            $cansetperms = $true
            try {
                Get-ADUser $folder.Name | Out-Null
            } catch {
                $cansetperms = $false
            }

            if (-not $cansetperms){ 
                Write-LogInfo -LogPath $sLogFile -Message "$user does not exist in AD, skipping permissions"
                continue
            }

            $acl = Get-Acl -Path $folder.FullName

            $perm = $user, 'CreateFiles,CreateDirectories', 'None', 'None', 'Deny'
            $rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $perm
            $acl.AddAccessRule($rule)
            Write-LogInfo -LogPath $sLogFile -Message "Set $user to be unable to create files or folders in $($folder.Fullname)"
            $perm = $user, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
            $rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $perm
            $acl.AddAccessRule($rule)
            Set-Acl -Path $folder.FullName -AclObject $acl
            Write-LogInfo -LogPath $sLogFile -Message "Set $user to have modify rights otherwise in $($folder.Fullname)"
            
            $confidentialfiles = $path + "\" + "Confidential Files"
            $acl = Get-Acl -Path $confidentialfiles
            $acl.SetAccessRuleProtection($true,$true)
            Set-Acl -Path $confidentialfiles -AclObject $acl

            $acl = Get-Acl -Path $confidentialfiles
            foreach ($access in $acl.Access){
                foreach($value in $access.IdentityReference.Value){
                    if ($value -like "DOMAIN\Domain Users"){
                        $acl.RemoveAccessRule($access)
                    }
                }
            }
            Write-LogInfo -LogPath $sLogFile -Message "Removed Domain Users permissions on $confidentialfiles"
            $perm = 'DONMAIN\Folder Access', 'Read', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
            $rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $perm
            $acl.AddAccessRule($rule)
            Set-Acl -Path $confidentialfiles -AclObject $acl
            Write-LogInfo -LogPath $sLogFile -Message "Set DOMAIN\Folder Access to have read only access to $confidentialfiles"

            #TIMESHEETS + PROGRESS RPT folder permissions

            $timesheets = $path + "\" + "Timesheets + Progress Rpt"
            $acl = Get-Acl -Path $timesheets
            $acl.SetAccessRuleProtection($true,$true)
            Set-Acl -Path $timesheets -AclObject $acl

            $acl = Get-Acl -Path $timesheets
            foreach ($access in $acl.Access){
                foreach($value in $access.IdentityReference.Value){
                    if ($value -like "DOMAIN\Domain Users"){
                        $acl.RemoveAccessRule($access)
                    }
                }
            }
            Write-LogInfo -LogPath $sLogFile -Message "Removed Domain Users permissions on $timesheets"
            $perm = 'DOMAINS\GROUP', 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
            $rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $perm
            $acl.AddAccessRule($rule)
            Set-Acl -Path $timesheets -AclObject $acl
            Write-LogInfo -LogPath $sLogFile -Message "Set DOMAINS\GROUP to have modify access to $timesheets"


        }
    }
    Catch {
      Write-LogError -LogPath $sLogFile -Message $_.Exception -ExitGracefully
      Break
    }
  }

  End {
    If ($?) {
      Write-LogInfo -LogPath $sLogFile -Message 'Completed Successfully.'
      Write-LogInfo -LogPath $sLogFile -Message ' '
      Stop-Log -LogPath $sLogFile -NoExit
    }
  }
}
