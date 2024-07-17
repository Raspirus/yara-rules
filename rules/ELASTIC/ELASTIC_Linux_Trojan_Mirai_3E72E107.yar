
rule ELASTIC_Linux_Trojan_Mirai_3E72E107 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "3e72e107-3647-4afd-a556-3c49dae7eb0c"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L597-L615"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "57d04035b68950246dd152054e949008dafb810f3705710d09911876cd44aec7"
		logic_hash = "ba0ba56ded8977502ad9f8a1ceebd30efbff964d576bbfeedff5761f0538d8f0"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3bca41fd44e5e9d8cdfb806fbfcaab3cc18baa268985b95e2f6d06ecdb58741a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 10 85 C0 BA FF FF FF FF 74 14 8D 65 F4 5B 5E 5F 89 D0 5D C3 8D }

	condition:
		all of them
}