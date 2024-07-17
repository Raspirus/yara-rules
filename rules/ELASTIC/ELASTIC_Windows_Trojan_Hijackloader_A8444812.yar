rule ELASTIC_Windows_Trojan_Hijackloader_A8444812 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Hijackloader (Windows.Trojan.HijackLoader)"
		author = "Elastic Security"
		id = "a8444812-6aef-4ed7-a44b-b147301544c8"
		date = "2023-11-15"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_HijackLoader.yar#L1-L24"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "065c379a33ef1539e8a68fd4b7638fe8a30ec19fc128642ed0c68539656374b9"
		logic_hash = "6cd88adc7a0d35013a26d1135efb294ee6f9ddab99b4549e82d3d6f5f65509b6"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "dd9f3bca44b585e3a31626b66223288634fcb092e43ecb053806726e5f2006e9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 8B 45 ?? 40 89 45 ?? 8B 45 ?? 3B 45 ?? 73 ?? 8B 45 ?? 03 45 ?? 66 0F BE 00 66 89 45 ?? FF 75 ?? FF 75 ?? 8D 45 ?? 50 E8 [4] 83 C4 0C EB ?? }
		$a2 = { 8B 45 ?? 8B 4D ?? 8B [1-5] 0F AF [1-5] 0F B7 [2] 03 C1 8B 4D ?? 89 01 }
		$a3 = { 33 C0 40 74 ?? 8B 45 ?? 8B 4D ?? 8B 55 ?? 03 14 81 89 55 ?? FF 75 ?? FF 75 ?? E8 [4] 59 59 89 45 ?? 8B 45 ?? 8B 4D ?? 0F B7 04 41 8B 4D ?? 8B 55 ?? 03 14 81 89 55 ?? 8B 45 ?? 3B 45 ?? 75 ?? 8B 45 ?? EB ?? 8B 45 ?? 40 89 45 ?? EB ?? }
		$a4 = { 8B 45 ?? 8B 4D ?? 8B [1-5] 0F AF [1-5] 0F B7 4D ?? 03 C1 8B 4D ?? 89 01 }
		$a5 = { 8B 45 ?? 83 C0 04 89 45 ?? 8B 45 ?? 3B 45 ?? 73 ?? 8B 45 ?? 8B 4D ?? 8B 04 81 03 45 ?? 8B 4D ?? 8B 55 ?? 89 04 8A 8B 45 ?? 40 89 45 ?? EB ?? }
		$a6 = { 8B 45 ?? 83 C0 04 89 45 ?? 8B 45 ?? 3B 45 ?? 73 ?? 8B 45 ?? 03 45 ?? 89 45 ?? 8B 45 ?? 8B 00 89 45 ?? 8B 45 ?? 33 45 ?? 8B 4D ?? 89 01 EB ?? }

	condition:
		3 of them
}