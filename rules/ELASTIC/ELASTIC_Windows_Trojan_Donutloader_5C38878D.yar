
rule ELASTIC_Windows_Trojan_Donutloader_5C38878D : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Donutloader (Windows.Trojan.Donutloader)"
		author = "Elastic Security"
		id = "5c38878d-ca94-4fd9-a36e-1ae5fe713ca2"
		date = "2021-09-15"
		modified = "2021-01-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Donutloader.yar#L21-L38"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "897880d13318027ac5008fe8d008f09780d6fa807d6cc828b57975443358750c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3b55ec6c37891880b53633b936d10f94d2b806db1723875e4ac95f8a34d97150"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 24 48 03 C2 48 89 44 24 28 41 8A 00 84 C0 74 14 33 D2 FF C1 }

	condition:
		any of them
}