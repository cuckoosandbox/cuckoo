rule UnicornGen {
  meta:
	author = "FDD @ Cuckoo Sandbox"
	description = "Rule for malcode generated with the Unicorn tool"
	ref = "https://github.com/trustedsec/unicorn"
  strings:
	$Import = "DllImport" nocase
	$Kernel32 = "kernel32.dll"
	$msvcrt = "msvcrt.dll"
	$fn1 = "VirtualAlloc"
	$fn2 = "CreateThread"
	$fn3 = "memset"
	$Shellcode = /=\s*((0x)?[0-9A-F]{2}\s*[,;]\s*)+/ nocase
  condition:
	all of them
}
