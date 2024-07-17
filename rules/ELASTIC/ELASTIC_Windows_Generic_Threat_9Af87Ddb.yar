rule ELASTIC_Windows_Generic_Threat_9Af87Ddb : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "9af87ddb-c3ed-44a5-b1a1-984b6f8a6065"
		date = "2024-05-23"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L3445-L3463"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b1fbc11744e21dc08599412887a3a966572614ce25ccd3c8c98f04bcbdda3898"
		logic_hash = "99174c5740324d7704a5c6ae924254f9b5f241c97901dfdb771fc176a76e4a30"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1505b6299961c729077ffd90a4c7ed3180f55329952841fe7045056ea2919de8"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 28 00 00 0A 28 2C 00 00 06 11 06 17 D6 13 06 11 06 11 07 8E B7 32 98 06 17 D6 0A 20 E8 03 00 00 28 21 00 00 0A 7E 0F 00 00 04 3A 74 FF FF FF 2A 00 1B 30 04 00 96 00 00 00 1F 00 00 11 03 39 88 }

	condition:
		all of them
}