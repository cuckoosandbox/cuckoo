rule PowershellEmpire {
  meta:
	author = "FDD"
	description = "Rule for Powershell Empire post-exploitation tool"
  strings:
	$UserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
	$UAString = "User-Agent"
	$Net = "new-object system.net.webclient" nocase
	$Download = "downloadstring(" nocase
	$Payload = /(https?|ftp):\/\/[^\s\/$.?#].[^\s'"]*/
  condition:
	all of them
}
