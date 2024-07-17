rule ELASTIC_Multi_Trojan_Sparkrat_9A21E541 : FILE MEMORY
{
	meta:
		description = "Detects Multi Trojan Sparkrat (Multi.Trojan.SparkRat)"
		author = "Elastic Security"
		id = "9a21e541-886c-4d7f-8602-832862121730"
		date = "2023-11-13"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Multi_Trojan_SparkRat.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "23efecc03506a9428175546a4b7d40c8a943c252110e83dec132c6a5db8c4dd6"
		logic_hash = "903c5c65436bea8dd044fd5f1f6dda3d1e90ab25802d508f67ba0f7fd06e92d4"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2691da3a037b651d0f7f6d7be767c34845c3b9a642f4a2fb1c54f391f08089b6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "multi"

	strings:
		$a1 = "Spark/client/service/file" ascii wide
		$a2 = "Spark/client/service/desktop" ascii wide
		$a3 = "Spark/utils.Encrypt" ascii wide

	condition:
		all of them
}