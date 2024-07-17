
rule ELASTIC_Windows_Trojan_Lurker_0Ee51802 : FILE
{
	meta:
		description = "Detects Windows Trojan Lurker (Windows.Trojan.Lurker)"
		author = "Elastic Security"
		id = "0ee51802-4ff3-4edf-95ed-bb0338ff25d9"
		date = "2022-04-04"
		modified = "2022-06-09"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Lurker.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5718fd4f807e29e48a8b6a6f4484426ba96c61ec8630dc78677686e0c9ba2b87"
		logic_hash = "782926c927dce82b95e51634d5607c474937e1edc0f7f739acefa0f4c03aa753"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "c30bc4e25c1984268a3bb44c59081131d1e81254b94734f6af2b47969c0acd0e"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "\\Device\\ZHWLurker0410" wide fullword

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}