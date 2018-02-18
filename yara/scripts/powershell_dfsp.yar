rule PowershellDFSP {
  meta:
	author = "FDD"
	description = "Rule for Powershell DFSP detection"
  strings:
	$Net = "new-object system.net.webclient" nocase
	$Download = "downloadfile(" nocase
	$Start = "Start-Process" nocase
	$Payload = /(https?|ftp):\/\/[^\s\/$.?#].[^\s"']*/
  condition:
	all of them
}
