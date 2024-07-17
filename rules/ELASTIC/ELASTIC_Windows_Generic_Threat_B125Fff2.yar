
rule ELASTIC_Windows_Generic_Threat_B125Fff2 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "b125fff2-7b36-431f-8ed3-ccb6d4ff9483"
		date = "2024-02-20"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2780-L2798"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "9c641c0c8c2fd8831ee4e3b29a2a65f070b54775e64821c50b8ccd387e602097"
		logic_hash = "054f3f36c688e1f5c3116e7a926df12df90f79dc1d42bee2616b5251f6ad2c24"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e2562c480b3ab0f0e6c5d396bc5d0584481348c1dd8edaac4484d9cb5d4a2b2e"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 6F 00 00 0A 6F 70 00 00 0A 00 28 24 00 00 06 0A 06 2C 24 00 28 1B 00 00 06 0B 07 2C 19 00 28 CE 04 00 06 16 FE 01 0C 08 2C 0B 7E 03 00 00 04 6F D3 04 00 06 00 00 00 28 1A 00 00 06 00 28 18 00 }

	condition:
		all of them
}