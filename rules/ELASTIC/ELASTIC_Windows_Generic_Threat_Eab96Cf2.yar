rule ELASTIC_Windows_Generic_Threat_Eab96Cf2 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "eab96cf2-f25a-4149-9328-3f7af50b2ad8"
		date = "2024-01-11"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L994-L1012"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2be8a2c524f1fb2acb2af92bc56eb9377c4e16923a06f5ac2373811041ea7982"
		logic_hash = "cc1dfc2c9c5e1fbc6282342dfbf3a6c834fa56fb6fc46569a24fa78535c5845f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a07bbc803aa7ae54d0c0b2b15edf8378646f06906151998ac3d5491245813dd9"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 20 41 52 FF E0 58 41 59 5A 48 8B 12 E9 4B FF FF FF 5D 48 31 DB 53 49 BE 77 69 6E 68 74 74 70 00 41 56 48 89 E1 49 C7 C2 4C 77 26 07 FF D5 53 53 48 89 E1 53 5A 4D 31 C0 4D 31 C9 53 53 }

	condition:
		all of them
}