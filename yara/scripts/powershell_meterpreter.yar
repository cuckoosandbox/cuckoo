rule PowershellMeterpreter {
  meta:
	author = "FDD"
	description = "Rule for Powershell DFSP detection"
  strings:
	$Net = "New-Object Net.WebClient" nocase
	$Download = "downloadstring(" nocase
	$Start = "Invoke-Shellcode" nocase
	$Iex = "iex" nocase
	$Package = /windows\/meterpreter\/[\w_]+/
	$Host = /Lhost\s+[^\s]+/
	$Port = /Lport\s+[^\s]+/
  condition:
	all of them
}
