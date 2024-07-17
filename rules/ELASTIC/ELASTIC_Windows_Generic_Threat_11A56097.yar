
rule ELASTIC_Windows_Generic_Threat_11A56097 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "11a56097-c019-43dc-b401-c3bd5e88ce17"
		date = "2024-01-12"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1014-L1033"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "98d538c8f074d831b7a91e549e78f6549db5d2c53a10dbe82209d15d1c2e9b56"
		logic_hash = "42f955c079752c787ac70682bc41fa31f3196d30051d7032276a0d4279d59d58"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "37fda03cc0d50dc8bf6adfb83369649047e73fe33929f6579bf806b343eb092c"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 6E 6F 69 74 70 65 63 78 45 74 61 6D 72 6F 46 65 67 61 6D 49 64 61 42 }
		$a2 = { 65 74 75 62 69 72 74 74 41 65 74 65 6C 6F 73 62 4F }

	condition:
		all of them
}