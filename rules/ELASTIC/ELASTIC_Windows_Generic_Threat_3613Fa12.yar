
rule ELASTIC_Windows_Generic_Threat_3613Fa12 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "3613fa12-b559-4c3f-8049-11bacd5ffd0c"
		date = "2024-02-20"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2760-L2778"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1403ec99f262c964e3de133a10815e34d2f104b113b0197ab43c6b7b40b536c0"
		logic_hash = "77b23aaf384de138214e64342e170f3dce667ee41c3063c999286da9af6fff42"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c66b5dad2e9b19be0bc67a652761d8f79ce85efde055cc412575c2d7c5583795"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 51 89 4D FC 8D 45 08 50 8B 4D FC E8 4D 03 00 00 8B 45 FC 8B E5 5D C2 04 00 CC CC CC CC 55 8B EC 51 89 4D FC 8B 45 FC 8B E5 5D C3 CC CC 55 8B EC 51 89 4D FC 8B 45 08 50 8B 4D FC E8 FD }

	condition:
		all of them
}