rule PowershellCcDns {
  meta:
	author = "FDD"
	description = "Rule for Powershell bot detection (C2 over DNS queries)"
  strings:
	$Start = "iex" nocase
	$DNS = /nslookup -q=txt [\w.]+/ nocase
  condition:
	all of them
}
