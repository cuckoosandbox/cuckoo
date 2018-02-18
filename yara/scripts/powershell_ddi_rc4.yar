rule PowershellDdiRc4 {
  meta:
	author = "FDD"
	description = "Rule for Powershell DDI RC4 detection"
  strings:
	$Net = "new-object system.net.webclient" nocase
	$Download = "downloaddata(" nocase
	$Start = "iex" nocase
	$Key = /\[system\.text\.encoding\]::ascii\.getbytes\(['"][^'"]+['"]\)/ nocase
	$Host = /(https?|ftp):\/\/[^\s\/$.?#].[^\s"']*/
	$Path = /['"](\/[^\/]+)+['"]/
  condition:
	all of them
}
