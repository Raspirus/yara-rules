
rule ELASTIC_Windows_Generic_Threat_76A7579F : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "76a7579f-4a9b-4dae-935c-14d829d3c416"
		date = "2024-01-09"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L834-L852"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "76c73934bcff7e4ee08b068d1e02b8f5c22161262d127de2b4ac2e81d09d84f6"
		logic_hash = "08ed2d318e7154195911aaf3705626307b48a54aa195eaa054ec53766d3e198d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ba5bfc0e012a22172f138c498560a606e6754efa0fa145799f00725e130ad90f"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 8B 55 10 8B 45 08 8B C8 85 D2 74 09 C6 01 00 41 83 EA 01 75 F7 5D C3 55 8B EC 64 A1 30 00 00 00 83 EC 18 8B 40 0C 53 56 57 8B 78 0C E9 A7 00 00 00 8B 47 30 33 F6 8B 5F 2C 8B 3F 89 45 }

	condition:
		all of them
}