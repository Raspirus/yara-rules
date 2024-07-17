
rule ELASTIC_Windows_Trojan_Emotet_Db7D33Fa : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Emotet (Windows.Trojan.Emotet)"
		author = "Elastic Security"
		id = "db7d33fa-e50c-4c59-ab92-edb74aac87c9"
		date = "2022-05-09"
		modified = "2022-06-09"
		reference = "https://www.elastic.co/security-labs/emotet-dynamic-configuration-extraction"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Emotet.yar#L64-L90"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "08c23400ff546db41f9ddbbb19fa75519826744dde3b3afb38f3985266577afc"
		logic_hash = "e220c112c15f384fde6fc2286b01c7eb9bedcf4817d02645d0fa7afb05e7b593"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "eac196154ab1ad636654c966e860dcd5763c50d7b8221dbbc7769c879daf02fd"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$chunk_0 = { 4C 8D 9C 24 ?? ?? ?? ?? 8B C3 49 8B 5B ?? 49 8B 73 ?? 49 8B 7B ?? 49 8B E3 5D C3 }
		$chunk_1 = { 8B C7 41 0F B7 4C 45 ?? 41 8B 1C 8C 48 03 DD 48 3B DE 72 ?? }
		$chunk_2 = { 48 8B C4 48 89 48 ?? 48 89 50 ?? 4C 89 40 ?? 4C 89 48 ?? C3 }
		$chunk_3 = { 48 8B 45 ?? BB 01 00 00 00 48 89 07 8B 45 ?? 89 47 ?? 4C 8D 9C 24 ?? ?? ?? ?? 8B C3 49 8B 5B ?? 49 8B 73 ?? 49 8B 7B ?? 49 8B E3 5D C3 }
		$chunk_4 = { 48 39 3B 4C 8D 9C 24 ?? ?? ?? ?? 49 8B 5B ?? 49 8B 73 ?? 40 0F 95 C7 8B C7 49 8B 7B ?? 49 8B E3 5D C3 }
		$chunk_5 = { BE 02 00 00 00 4C 8D 9C 24 ?? ?? ?? ?? 8B C6 49 8B 5B ?? 49 8B 73 ?? 49 8B 7B ?? 49 8B E3 41 5F 41 5E 41 5D 41 5C 5D C3 }
		$chunk_6 = { 43 8B 84 FE ?? ?? ?? ?? 48 03 C6 48 3B D8 73 ?? }
		$chunk_7 = { 88 02 48 FF C2 48 FF C3 8A 03 84 C0 75 ?? EB ?? }

	condition:
		4 of them
}