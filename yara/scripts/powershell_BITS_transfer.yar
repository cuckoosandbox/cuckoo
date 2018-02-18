rule PowershellBitsTransfer {
  meta:
	author = "FDD @ Cuckoo Sandbox"
	description = "Rule for Powershell BITS Transfer detection"
  strings:
	$Module = "Import-Module BitsTransfer" nocase
	$Download = "Start-BitsTransfer" nocase
	$Start = "Invoke-Item" nocase
	$Payload = /(https?|ftp):\/\/[^\s\/$.?#].[^\s"']*/
  condition:
	all of them
}
