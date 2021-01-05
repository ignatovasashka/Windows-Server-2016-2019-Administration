# Exam-Summary.ps1
#
# VERSION: 2019.01.27

#
# Falues to search for
#

$tCOMPUTER1 = "MASTER"
$tCOMPUTER2 = "SLAVE"
$tFQDN2 = "SLAVE.WSA.EXAM"
$tDOMAIN = "WSA.EXAM"
$tDOMAINP1 = "EXAM"
$tDOMAINP2 = "WSA"
$tNICEXT = "NIC-EXT"
$tNICINT = "NIC-INT"
$tLANADDR = "192.168.240.1"
$tSCOPENAME = "Exam Pool"
$tSCOPESTART = "192.168.240.2"
$tSCOPEEND = "192.168.240.10"
$tOUUSERS = "Exam Users"
$tOUCOMPUTERS = "Exam Computers"
$tOUGROUPS = "Exam Groups"
$tOU1 = "IT"
$tOU2 = "Sales"
$tUSER1 = "trayan.stoev"
$tUSER2 = "tsvetanka.hristova"
$tGROUP1 = "GS IT"
$tGROUP2 = "GS Sales"
$tGROUP3 = "GS Web"

#
# Variables section
#
$Tasks = (3, 1, 1, 2, 3, 1, 3, 2, 1, 2, 1, 1, 1, 1, 2, 2, 2, 2, 3, 4, 2, 2, 3, 3, 2, 2, 5, 3)
$Labels = ('T101', 'T102', 'T103', 'T104', 'T105', 'T106', 'T107', 'T201',  'T202', 'T203', 'T204', 'T205', 'T206', 'T207', 'T208', 'T209', 'T210', 'T301', 'T302', 'T303', 'T304', 'T305', 'T401', 'T402', 'T403', 'T404', 'T501', 'T502')
$CurrentTask = 0
$CurrentScore = 0
$MaxScore = 60
$ExamLog = "C:\Exam\Exam-Log-$(Get-Date -Format "yyyy-MM-dd-hh-mm").txt"
$SoftUniUser = Read-Host -Prompt "Enter your SoftUni user name:"

function Print-Decision($t)
{
    if ($t -eq $true) 
    {
        "* Task $($CurrentTask+1) ($($Labels[$CurrentTask])): Ok" | %{Write-Host $_; Out-File -InputObject $_ -FilePath $ExamLog -Append}
        $global:CurrentScore = $global:CurrentScore + $Tasks[$CurrentTask]
    }
    else 
    {
        "* Task $($CurrentTask+1): NOT Ok" | %{Write-Host $_; Out-File -InputObject $_ -FilePath $ExamLog -Append}
        if (Select-String -Path C:\Exam\Task-$($CurrentTask+1).txt -Pattern OK)
        {
            "*** Task $($CurrentTask+1): OVERRIDDEN!" | %{Write-Host $_; Out-File -InputObject $_ -FilePath $ExamLog -Append}
            $global:CurrentScore = $global:CurrentScore + $Tasks[$CurrentTask]
        }
    }
}


# 
# Check and setup prerequisites
#
New-Item -ItemType Directory -Force -Path C:\Exam | Out-Null

"# Exam data for $SoftUniUser" | %{Write-Host $_; Out-File -InputObject $_ -FilePath $ExamLog -Force -Append}

"# Prerequisites" | %{Write-Host $_; Out-File -InputObject $_ -FilePath $ExamLog -Append}
if (Get-WindowsFeature Web-Mgmt-Console | Where Installed)
{
    "* Check if IIS module is present" | %{Write-Host $_; Out-File -InputObject $_ -FilePath $ExamLog -Append}
}
else
{
    "* IIS module not found. Installing it ..." | %{Write-Host $_; Out-File -InputObject $_ -FilePath $ExamLog -Append}
    Install-WindowsFeature Web-Mgmt-Console
}

"* Import IIS module" | %{Write-Host $_; Out-File -InputObject $_ -FilePath $ExamLog -Append}
Import-Module WebAdministration


#
# Section: Infrastructure (14 pts)
#
"# Infrastructure" | %{Write-Host $_; Out-File -InputObject $_ -FilePath $ExamLog -Append}

#
# Test for Task 1 (T101)
#
$v = $false
if ($env:COMPUTERNAME -Eq $tCOMPUTER1) { $v=$true }
Print-Decision($v)
$CurrentTask = $CurrentTask + 1


#
# Test for Task 2 (T102)
# 
$v = $false
if (Get-NetAdapter -Name $tNICEXT | Get-NetIPAddress -AddressFamily IPv4 | Select -Property PrefixOrigin | Where PrefixOrigin -Eq "Dhcp") { $v=$true }
Print-Decision($v)
$CurrentTask = $CurrentTask + 1


#
# Test for Task 3 (T103)
#
$v = $false
if (Get-NetAdapter -Name $tNICINT | Get-NetIPAddress -AddressFamily IPv4 | Select -Property IPAddress | Where IPAddress -Eq $tLANADDR) { $v = $true }
Print-Decision($v)
$CurrentTask = $CurrentTask + 1

#
# Test for Task 4 (T104)
#
$v = $false
if ((Get-DhcpServerv4Scope | Where Name -Eq $tSCOPENAME | Where StartRange -Eq $tSCOPESTART | Where EndRange -Eq $tSCOPEEND) -And
   (Get-DhcpServerv4Binding | Where InterfaceAlias -Eq $tNICINT)) { $v = $true }
Print-Decision($v)
$CurrentTask = $CurrentTask + 1

#
# Test for Task 5 (T105)
#
$v = $false
if ((Get-WindowsFeature AD-Domain-Services | Where Installed) -And
   (Get-ADDomain | Where DNSRoot -Eq $tDOMAIN.ToLower())) { $v = $true }
Print-Decision($v)
$CurrentTask = $CurrentTask + 1

#
# Test for Task 6 (T106)
#
$v = $false
if (Get-WindowsFeature DNS | Where Installed) { $v = $true }
Print-Decision($v)
$CurrentTask = $CurrentTask + 1

#
# Test for Task 7 (T107)
#
$v = $false
if (Test-Connection -ComputerName $tCOMPUTER2 -Count 1 -Quiet) { $v = $true }
Print-Decision($v)
$CurrentTask = $CurrentTask + 1


#
# Section: Users and Groups (15 pts)
#
"# Users and Groups" | %{Write-Host $_; Out-File -InputObject $_ -FilePath $ExamLog -Append}

#
# Test for Task 8 (T201)
#
$v = $false
if ((Get-ADOrganizationalUnit -Identity "OU=$tOUUSERS, DC=$tDOMAINP2, DC=$tDOMAINP1") -And 
    (Get-ADOrganizationalUnit -Identity "OU=$tOU1, OU=$tOUUSERS, DC=$tDOMAINP2, DC=$tDOMAINP1") -And
    (Get-ADOrganizationalUnit -Identity "OU=$tOU2, OU=$tOUUSERS, DC=$tDOMAINP2, DC=$tDOMAINP1")) { $v = $true }
Print-Decision($v)
$CurrentTask = $CurrentTask + 1

#
# Test for Task 9 (T202)
#
$v = $false
if (Get-ADDomain | Select UsersContainer | Where UsersContainer -Like "OU=$tOUUSERS*") { $v = $true }
Print-Decision($v)
$CurrentTask = $CurrentTask + 1

#
# Test for Task 10 (T203)
#
$v = $false
if ((Get-ADOrganizationalUnit -Identity "OU=$tOUCOMPUTERS, DC=$tDOMAINP2, DC=$tDOMAINP1") -And 
    (Get-ADOrganizationalUnit -Identity "OU=$tOU1, OU=$tOUCOMPUTERS, DC=$tDOMAINP2, DC=$tDOMAINP1") -And
    (Get-ADOrganizationalUnit -Identity "OU=$tOU2, OU=$tOUCOMPUTERS, DC=$tDOMAINP2, DC=$tDOMAINP1")) { $v = $true }
Print-Decision($v)
$CurrentTask = $CurrentTask + 1

#
# Test for Task 11 (T204)
#
$v = $false
if (Get-ADDomain | Select ComputersContainer | Where ComputersContainer -Like "OU=$tOUCOMPUTERS*") { $v = $true }
Print-Decision($v)
$CurrentTask = $CurrentTask + 1

#
# Test for Task 12 (T205)
#
$v = $false
if (Get-ADUser -Filter {Name -Like "*trayan*"} -SearchBase "OU=$tOU1, OU=$tOUUSERS, DC=$tDOMAINP2, DC=$tDOMAINP1") { $v = $true }
Print-Decision($v)
$CurrentTask = $CurrentTask + 1

#
# Test for Task 13 (T206)
#
$v = $false
if (Get-ADUser -Filter {Name -Like "*tsvetanka*"} -SearchBase "OU=$tOU2, OU=$tOUUSERS, DC=$tDOMAINP2, DC=$tDOMAINP1") { $v = $true }
Print-Decision($v)
$CurrentTask = $CurrentTask + 1

#
# Test for Task 14 (T207)
#
$v = $false
if (Get-ADOrganizationalUnit -Identity "OU=$tOUGROUPS, DC=$tDOMAINP2, DC=$tDOMAINP1") { $v = $true }
Print-Decision($v)
$CurrentTask = $CurrentTask + 1

#
# Test for Task 15 (T208)
#
$v = $false
if (Get-ADGroup -Filter {Name -Like $tGROUP1 -And GroupScope -Eq "Global"} -SearchBase "OU=$tOUGROUPS, DC=$tDOMAINP2, DC=$tDOMAINP1" | Get-ADGroupMember | Select -Property Name | Where Name -Like "*trayan*") { $v = $true }
Print-Decision($v)
$CurrentTask = $CurrentTask + 1

#
# Test for Task 16 (T209)
#
$v = $false
if (Get-ADGroup -Filter {Name -Like $tGROUP2 -And GroupScope -Eq "Global"} -SearchBase "OU=$tOUGROUPS, DC=$tDOMAINP2, DC=$tDOMAINP1" | Get-ADGroupMember | Select -Property Name | Where Name -Like "*tsvetanka*") { $v = $true }
Print-Decision($v)
$CurrentTask = $CurrentTask + 1

#
# Test for Task 17 (T210)
#
$v = $false
if (Get-ADGroup -Filter {Name -Like $tGROUP3 -And GroupScope -Eq "Global"} -SearchBase "OU=$tOUGROUPS, DC=$tDOMAINP2, DC=$tDOMAINP1" | Get-ADGroupMember | Select -Property Name | Where Name -Like "*slave*") { $v = $true }
Print-Decision($v)
$CurrentTask = $CurrentTask + 1


#
# Section: Additional Services (13 pts)
#
"# Additional Services" | %{Write-Host $_; Out-File -InputObject $_ -FilePath $ExamLog -Append}

#
# Test for Task 18 (T301)
#
$v = $false
if (Get-WindowsFeature -ComputerName SLAVE -Name *Web-Server* | Where Installed) { $v = $true }
Print-Decision($v)
$CurrentTask = $CurrentTask + 1

#
# Test for Task 19 (T302)
#
$v = $false
if (Invoke-Command -ComputerName SLAVE {Get-WebBinding -Port 8080}) { $v = $true }
Print-Decision($v)
$CurrentTask = $CurrentTask + 1

#
# Test for Task 20 (T303)
#
$v = $false
if ((Invoke-Command -ComputerName SLAVE { Get-SmbShareAccess -Name "Common" | Where -Property AccountName -Eq Everyone | Where -Property AccessRight -Eq Full}) -And
   (Invoke-Command -ComputerName SLAVE {Get-Item C:\Common | Get-Acl | Select * | Where AccessToString -Like "Everyone*Allow*Full*"})) { $v = $true }
Print-Decision($v)
$CurrentTask = $CurrentTask + 1

#
# Test for Task 21 (T304)
#
$v = $false
if ((Invoke-Command -ComputerName SLAVE {Get-Item C:\Common\IT | Get-Acl | Select * | Where AccessToString -Like "*GS*IT*Allow*Full*"}) -And
   (Invoke-Command -ComputerName SLAVE {Get-Item C:\Common\IT | Get-Acl | Select * | Where AccessToString -Like "*GS*Sales*Deny*"})) { $v = $true }
Print-Decision($v)
$CurrentTask = $CurrentTask + 1

#
# Test for Task 22 (T305)
#
$v = $false
if ((Invoke-Command -ComputerName SLAVE {Get-Item C:\Common\Sales | Get-Acl | Select * | Where AccessToString -Like "*GS*Sales*Allow*Full*"}) -And
   (Invoke-Command -ComputerName SLAVE {Get-Item C:\Common\Sales | Get-Acl | Select * | Where AccessToString -Like "*GS*IT*Deny*"})) { $v = $true }
Print-Decision($v)
$CurrentTask = $CurrentTask + 1


#
# Section: GPO and Security (10 pts)
#
"# GPO and Security" | %{Write-Host $_; Out-File -InputObject $_ -FilePath $ExamLog -Append}

#
# Test for Task 23 (T401)
#
$v = $false
if (Get-GPRegistryValue -Name GPO-Remote -Key "HKLM\Software\Policies\Microsoft\WindowsFirewall\FirewallRules" | Where -Property ValueName -Like "*WINRM*") { $v = $true }
Print-Decision($v)
$CurrentTask = $CurrentTask + 1

#
# Test for Task 24 (T402)
#
$v = $false
if (Get-GPRegistryValue -Name GPO-IIS -Key "HKLM\Software\Policies\Microsoft\WindowsFirewall\FirewallRules" | Where -Property Value -Like "*8080*") { $v = $true }
Print-Decision($v)
$CurrentTask = $CurrentTask + 1

#
# Test for Task 25 (T403)
#
$v = $false
$report = Get-GPOReport -Name GPO-Drive -ReportType Xml
if ($report.Contains("\\SLAVE\Common")) { $v = $true }
Print-Decision($v)
$CurrentTask = $CurrentTask + 1

#
# Test for Task 26 (T404)
#
$v = $false
$report = Get-GPOReport -Name GPO-Wallpaper -ReportType Xml
if ($report.Contains("wallpaper.png")) { $v = $true }
Print-Decision($v)
$CurrentTask = $CurrentTask + 1


#
# Section: Scripting (8 pts)
#
"# Scripting" | %{Write-Host $_; Out-File -InputObject $_ -FilePath $ExamLog -Append}

#
# Test for Task 27 (T501)
#
$v = $false
if (Select-String -Path C:\Scripts\Track-Performance.ps1 -Pattern counter) { $v = $true }
Print-Decision($v)
$CurrentTask = $CurrentTask + 1

#
# Test for Task 28 (T502)
#
$v = $false
if ((Get-ScheduledTask -TaskName *Track*Performance*).Triggers[0].Repetition | Where -Property Interval -Eq PT5M) { $v = $true }
Print-Decision($v)
$CurrentTask = $CurrentTask + 1


#
# Section: Test end
#
"# Final Score: $CurrentScore" | %{Write-Host $_; Out-File -InputObject $_ -FilePath $ExamLog -Append}