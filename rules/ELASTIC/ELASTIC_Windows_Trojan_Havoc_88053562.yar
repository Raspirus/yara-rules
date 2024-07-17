rule ELASTIC_Windows_Trojan_Havoc_88053562 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Havoc (Windows.Trojan.Havoc)"
		author = "Elastic Security"
		id = "88053562-ae19-44fe-8aaf-d6b9687d6b80"
		date = "2024-01-04"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Havoc.yar#L58-L76"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2f0b59f8220edd0d34fba92905faf0b51aead95d53be8b5f022eed7e21bdb4af"
		logic_hash = "f79b39cc2ca4bbf6ad4b6585a9914a75797110d6fb68bcb7141c5c3d0429c412"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "818011b7972ab71cbfe07ec2266f504ba0ec7df30136e414d15366aa68ad5b8a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 48 81 EC F8 04 00 00 48 8D 7C 24 78 44 89 8C 24 58 05 00 00 48 8B AC 24 60 05 00 00 4C 8D 6C 24 78 F3 AB B9 59 00 00 00 48 C7 44 24 70 00 00 00 00 C7 44 24 78 68 00 00 00 C7 84 24 B4 00 00 00 }

	condition:
		all of them
}