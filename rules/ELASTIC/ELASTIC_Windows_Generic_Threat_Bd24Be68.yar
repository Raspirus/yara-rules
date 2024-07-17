rule ELASTIC_Windows_Generic_Threat_Bd24Be68 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "bd24be68-3d72-44fd-92f2-39f592d47d0e"
		date = "2024-01-12"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1200-L1218"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "fd159cf2f9bd48b0f6f5958eef8af8feede2bcbbea035a7e56ce1ff72d3f47eb"
		logic_hash = "8536593696930d03f1e62586886f0df5438d13fb796b4605df7ad67d9633d5f9"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "35ff6c9b338ef95585d8d0059966857f6e5a426fa5f357acb844d264d239c70d"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 8B 4D 0C 56 8B 75 08 89 0E E8 AB 17 00 00 8B 48 24 89 4E 04 E8 A0 17 00 00 89 70 24 8B C6 5E 5D C3 55 8B EC 56 E8 8F 17 00 00 8B 75 08 3B 70 24 75 0E 8B 76 04 E8 7F 17 00 00 89 70 24 }

	condition:
		all of them
}