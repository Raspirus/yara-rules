
rule ELASTIC_Windows_Trojan_Grandoreiro_51236Ba2 : FILE MEMORY
{
	meta:
		description = "Grandoreiro rule, target loader and payload"
		author = "Elastic Security"
		id = "51236ba2-fdbc-4c46-b57b-27fc1e135486"
		date = "2022-08-23"
		modified = "2023-06-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Grandoreiro.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1bdf381e7080d9bed3f52f4b3db1991a80d3e58120a5790c3d1609617d1f439e"
		logic_hash = "9a8549a1dd82f56458ea8aee5c30243ac073d15c820de28d78a58d2c067b10d6"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c3082cc865fc177d8cbabcfcf9fb67317af5f2d28e8eeb95eb04108a558d80d4"
		threat_name = "Windows.Trojan.Grandoreiro"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$antivm0 = { B8 68 58 4D 56 BB 12 F7 6C 3C B9 0A 00 00 00 66 BA 58 56 ED B8 01 00 00 00 }
		$antivm1 = { B9 [4] 89 E5 53 51 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 BB 00 00 00 00 B8 01 00 00 00 0F 3F 07 0B }
		$xor0 = { 0F B7 44 70 ?? 33 D8 8D 45 ?? 50 89 5D ?? }
		$xor1 = { 8B 45 ?? 0F B7 44 70 ?? 33 C3 89 45 ?? }

	condition:
		all of them
}