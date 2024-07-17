
rule ELASTIC_Windows_Trojan_Sliver_C9Cae357 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Sliver (Windows.Trojan.Sliver)"
		author = "Elastic Security"
		id = "c9cae357-9270-4871-8fad-d9c43dcab644"
		date = "2023-05-10"
		modified = "2023-06-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Sliver.yar#L22-L40"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "27210d8d6e16c492c2ee61a59d39c461312f5563221ad4a0917d4e93b699418e"
		logic_hash = "fea862352981787055961b1171de9b69a9c13d246f434809c8f4416d5c49a0ff"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "5366540c4a4f4a502b550f5397f3b53e3bc909cbc0cb82a2091cabb19bc135aa"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { B1 F9 3C 0A 68 0F B4 B5 B5 B5 21 B2 38 23 29 D8 6F 83 EC 68 51 8E }

	condition:
		all of them
}