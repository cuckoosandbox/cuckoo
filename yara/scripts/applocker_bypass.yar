rule ApplockerBypass {
  meta:
	author = "Jurriaan Bremer"
	description = "Powershell AppLocker Bypass"
  strings:
    $cmdline = /regsvr32[^;]+\/i:(https?|ftp):\/\/[^\s\/$.?#].[^\s\"']+[\s]+\w+\.dll/
  condition:
	all of them
}
