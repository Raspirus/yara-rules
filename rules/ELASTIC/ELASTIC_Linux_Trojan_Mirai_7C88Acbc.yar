rule ELASTIC_Linux_Trojan_Mirai_7C88Acbc : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "7c88acbc-8b98-4508-ac53-ab8af858660d"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L279-L296"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "76373f8e09b7467ac5d36e8baad3025a57568e891434297e53f2629a72cf8929"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e2ef1c60e21f18e54694bcfc874094a941e5f61fa6144c5a0e44548dafa315be"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = "[Cobalt][%s][%s][%s][%s]"

	condition:
		all of them
}