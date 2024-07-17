
rule ELASTIC_Windows_Trojan_Backoff_22798F00 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Backoff (Windows.Trojan.Backoff)"
		author = "Elastic Security"
		id = "22798f00-ff2a-4f5f-a9ef-fab6d04ca679"
		date = "2022-08-10"
		modified = "2022-09-29"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Backoff.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "65b5aff18a4e0bc29d7cc4cfbe2d5882f99a855727fe467b2ba2e2851c43d21b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a45fc701844e6e0cfba5d8ef90d00960b5817af66e6b3d889a54d33539cd5d41"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "\\nsskrnl" fullword
		$str2 = "Upload KeyLogs" fullword
		$str3 = "&op=%d&id=%s&ui=%s&wv=%d&gr=%s&bv=%s" fullword
		$str4 = "[%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]" fullword
		$str5 = "\\OracleJava\\Log.txt" fullword
		$str6 = "[Ctrl+%c]" fullword

	condition:
		3 of them
}