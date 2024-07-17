
rule ELASTIC_Macos_Trojan_Generic_A829D361 : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Generic (MacOS.Trojan.Generic)"
		author = "Elastic Security"
		id = "a829d361-ac57-4615-b8e9-16089c44d7af"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Generic.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5b2a1cd801ae68a890b40dbd1601cdfeb5085574637ae8658417d0975be8acb5"
		logic_hash = "70a954e8b44b1ce46f5ce0ebcf43b46e1292f0b8cdb46aa67f980d3c9b0a6f61"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "5dba43dbc5f4d5ee295e65d66dd4e7adbdb7953232faf630b602e6d093f69584"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { E7 81 6A 12 EA A8 56 6C 86 94 ED F6 E8 D7 35 E1 EC 65 47 BA 8E 46 2C A6 14 5F }

	condition:
		all of them
}