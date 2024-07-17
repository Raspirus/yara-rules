
rule ELASTIC_Windows_Generic_Threat_Fdbcd3F2 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "fdbcd3f2-17e6-49d4-997b-91e6a85e4226"
		date = "2024-01-17"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1320-L1338"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "9258e4fe077be21ad7ae348868f1ac6226f6e9d404c664025006ab4b64222369"
		logic_hash = "ca9136ca44a61795cca44ac9bb0494fdc34c08d6578603ba3be3582956f4a98f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2a69deed3fe05b64cb37881ce50cae8972e7a610fd32c4b7f9155409bc5b297c"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 83 C4 FC 60 8B 75 0C 8D A4 24 00 00 00 00 8D A4 24 00 00 00 00 90 56 E8 22 00 00 00 0B C0 75 05 89 45 FC EB 11 89 35 84 42 40 00 46 8B 5D 08 38 18 75 E3 89 45 FC 61 8B 45 FC C9 C2 08 }

	condition:
		all of them
}