rule ELASTIC_Windows_Trojan_Clipbanker_787B130B : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Clipbanker (Windows.Trojan.Clipbanker)"
		author = "Elastic Security"
		id = "787b130b-6382-42f0-8822-fce457fa940d"
		date = "2022-04-24"
		modified = "2022-06-09"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Clipbanker.yar#L65-L87"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0407e8f54490b2a24e1834d99ec0452f217499f1e5a64de3d28439d71d16d43c"
		logic_hash = "88783bde7014853f6556c6e7ee2dfd5cd5fcbfb4523ed158b4287e2bfba409f1"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "15f3c7d5f25982a02a6bca0b550b3b65e1e21efa5717a1ea0c13dfe46b8f2699"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$mutex_setup = { 55 8B EC 83 EC ?? 53 56 57 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 3D ?? ?? ?? ?? 75 ?? 6A ?? FF 15 ?? ?? ?? ?? }
		$new_line_check = { 0F B7 C2 89 45 ?? 0F B7 C2 83 F8 0A 74 ?? BA 0D 0A 00 00 66 3B C2 74 ?? 83 F8 0D 74 ?? 83 F8 20 74 ?? 83 F8 09 74 ?? }
		$regex1 = { 0F B7 C2 89 45 ?? 0F B7 C2 83 F8 0A 74 ?? BA 0D 0A 00 00 66 3B C2 74 ?? 83 F8 0D 74 ?? 83 F8 20 74 ?? 83 F8 09 74 ?? }
		$regex2 = { 6A 34 59 66 39 0E 75 ?? 0F B7 46 ?? 6A 30 5A 83 F8 41 74 ?? 83 F8 42 74 ?? 66 3B C2 74 ?? 83 F8 31 74 ?? 83 F8 32 74 ?? 83 F8 33 74 ?? 66 3B C1 74 ?? 83 F8 35 74 ?? 83 F8 36 74 ?? 83 F8 37 74 ?? 83 F8 38 74 ?? 83 F8 39 75 ?? }
		$regex3 = { 56 8B F1 56 FF 15 ?? ?? ?? ?? 83 F8 5F 0F 85 ?? ?? ?? ?? 6A 38 59 66 39 0E 75 ?? 0F B7 46 ?? 6A 30 5A 83 F8 41 74 ?? 83 F8 42 74 ?? 66 3B C2 74 ?? 83 F8 31 74 ?? 83 F8 32 74 ?? 83 F8 33 74 ?? 83 F8 34 74 ?? 83 F8 35 74 ?? 83 F8 36 74 ?? 83 F8 37 74 ?? 66 3B C1 74 ?? 83 F8 39 75 ?? }

	condition:
		any of them
}