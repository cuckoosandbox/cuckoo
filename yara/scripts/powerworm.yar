rule PowerWorm {
	meta:
		author = "FDD @ Cuckoo Sandbox"
		description = "Rule for PowerWorm script detection"

	strings:
		/* .onion URL for payload */
		$payload = /(https?|ftp):\/\/[^\s\/$.?#].[^\s'"]*/
		$uuid = "(get-wmiobject Win32_ComputerSystemProduct).UUID" nocase
		$run = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
		$tor = "Bootstrapped 100%: Done."
		$socks = "socksParentProxy=localhost:"
		$proxy = "New-Object System.Net.WebProxy" nocase
		/* PowerWorm uses junk strings in between code to obfuscate it */
		$junk = /;('|")[^'"]+('|")/

	condition:
		all of them
}
