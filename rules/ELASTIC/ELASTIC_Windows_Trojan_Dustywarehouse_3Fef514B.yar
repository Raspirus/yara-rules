rule ELASTIC_Windows_Trojan_Dustywarehouse_3Fef514B : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Dustywarehouse (Windows.Trojan.DustyWarehouse)"
		author = "Elastic Security"
		id = "3fef514b-9499-47ce-bf84-8393f8d0260f"
		date = "2024-05-30"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_DustyWarehouse.yar#L25-L43"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4ad024f53595fdd380f5b5950b62595cd47ac424d2427c176a7b2dfe4e1f35f7"
		logic_hash = "865ea1e54950a465b71939a41f7a726ccddcfa9f0d777ea853926f65bca0da84"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "077bc59b4b6298e405c1cd37d9416667371190e5d8c83a9a9502753c9065df58"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 48 83 EC 30 48 C7 44 24 20 FE FF FF FF 48 89 5C 24 48 48 89 74 24 50 C7 44 24 40 [4] 48 8B 39 48 8B 71 08 48 8B 59 10 48 8B 49 18 ?? ?? ?? ?? ?? ?? 84 DB 74 05 E8 E1 01 00 00 48 8B CE }

	condition:
		all of them
}