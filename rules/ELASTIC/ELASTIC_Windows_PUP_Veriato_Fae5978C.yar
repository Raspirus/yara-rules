rule ELASTIC_Windows_PUP_Veriato_Fae5978C : FILE MEMORY
{
	meta:
		description = "Detects Windows Pup Veriato (Windows.PUP.Veriato)"
		author = "Elastic Security"
		id = "fae5978c-f26c-4215-9407-d16e492ab5c1"
		date = "2022-06-08"
		modified = "2022-09-29"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_PUP_Veriato.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "53f09e60b188e67cdbf28bda669728a1f83d47b0279debf3d0a8d5176479d17f"
		logic_hash = "8ae6f8b2b6e3849b33e6a477af52982efe137d7ebeff0c92cee5667d75f05145"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8d351cdd11d6dddc76cd89e7de9e65b28ef5c8183db804b2a450095e2f3214e5"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$s1 = "InitializeDll" fullword
		$a1 = "C:\\Windows\\winipbin\\svrltmgr.dll" fullword
		$a2 = "C:\\Windows\\winipbin\\svrltmgr64.dll" fullword

	condition:
		$s1 and ($a1 or $a2)
}