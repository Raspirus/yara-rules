
rule ELASTIC_Windows_Generic_Threat_85C73807 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "85c73807-4181-4d4a-ba51-6ed923121486"
		date = "2024-02-20"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2660-L2678"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "7f560a22c1f7511518656ac30350229f7a6847d26e1b3857e283f7dcee2604a0"
		logic_hash = "90aa64f17b91ccdf367e1976cd1f5e89e15c7369a58b2d19187143e70939d756"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8b63723aa1b89149c360048900a18e25a0a615f50cec1aaadca2578684f5bcb2"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 51 53 56 57 89 4D FC 8B DA 8B F0 8B 7D 08 C6 86 18 01 00 00 00 8B C3 E8 15 01 00 00 84 C0 75 0E 8B 55 FC 8B C6 8B CF E8 45 F8 FF FF EB 0F 56 57 8B FE 8B F3 B9 47 00 00 00 F3 A5 5F 5E }

	condition:
		all of them
}