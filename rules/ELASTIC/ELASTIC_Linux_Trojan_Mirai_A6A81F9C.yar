
rule ELASTIC_Linux_Trojan_Mirai_A6A81F9C : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "a6a81f9c-b43b-4ec3-8b0b-94c1cfee4f08"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L755-L772"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "0d31cc1f4a673c13e6c81c492acbe16e1e0dfb0b15913fb276ea4abff18b32af"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e1ec5725b75e4bb3eefe34a17ced900a16af9329a07a99f18f88aaef2678bfc1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 41 57 00 54 43 50 00 47 52 45 00 4B 54 00 73 68 65 6C 6C 00 }

	condition:
		all of them
}