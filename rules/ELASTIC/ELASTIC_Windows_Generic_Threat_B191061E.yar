
rule ELASTIC_Windows_Generic_Threat_B191061E : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "b191061e-7b83-4161-a1d4-05ab70ffe2be"
		date = "2024-03-04"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2963-L2981"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "bd4ef6fae7f29def8e5894bf05057653248f009422de85c1e425d04a0b2df258"
		logic_hash = "cbee10eab984249ceb9f8a82dc06aa014d6a249321f3d4f0d1e5657aab205ec8"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "5733de0357a6b5f6a3fe885786084c23707266b48e67b19dcddc48ed97e94207"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 83 EC 2C 64 A1 30 00 00 00 33 D2 53 56 57 8B 40 0C 8B F2 89 4D E8 89 55 F4 89 75 F8 8B 58 0C 8B 7B 18 89 7D F0 85 FF 0F 84 34 01 00 00 C7 45 E0 60 00 00 00 8B 43 30 89 55 FC 89 55 EC }

	condition:
		all of them
}