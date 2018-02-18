rule PowershellAMSI {
  meta:
	author = "FDD"
	description = "Powershell AMSI Bypass"
  strings:
	$obj1 = "assembly" nocase
	$fn1 = "GetType('System.Management.Automation.AmsiUtils')" nocase
	$fn2 = "GetField('amsiInitFailed','NonPublic,Static')" nocase
	$fn3 = "SetValue($Null,$True)" nocase
  condition:
	all of them
}
