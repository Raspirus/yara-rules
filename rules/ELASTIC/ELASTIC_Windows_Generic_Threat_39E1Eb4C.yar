
rule ELASTIC_Windows_Generic_Threat_39E1Eb4C : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "39e1eb4c-32ba-4c78-9997-1c75b41dcba6"
		date = "2024-01-24"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2111-L2129"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a733258bf04ffa058db95c8c908a79650400ebd92600b96dd28ceecac311f94a"
		logic_hash = "d7791ae7513bc5645bcfa93a2d7bf9f7ef47a6727ea2ba5eb85f3c8528761429"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "63d21d89b4ceea1fbc44a1dfd2dbb9ac3eb945884726a9809133624b10168c7a"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 83 E4 F8 83 EC 6C 53 56 8B 75 08 57 8B C6 8D 4C 24 58 E8 26 80 00 00 8B C6 8D 4C 24 38 E8 1B 80 00 00 80 7C 24 54 00 8B 7E 0C 8B 5E 08 89 7C 24 1C 74 09 8B 74 24 50 E8 61 80 00 00 83 }

	condition:
		all of them
}