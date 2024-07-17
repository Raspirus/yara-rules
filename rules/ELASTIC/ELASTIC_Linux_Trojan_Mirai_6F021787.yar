rule ELASTIC_Linux_Trojan_Mirai_6F021787 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "6f021787-9c2d-4536-bd90-5230c85a8718"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L100-L118"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "88183d71359c16d91a3252085ad5a270ad3e196fe431e3019b0810ecfd85ae10"
		logic_hash = "7e8062682a0babbaa3c00975807ba9fc34c465afde55e4144944e7598f0ea1fd"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "33ba39b77e55b1a2624e7846e06b2a820de9a8a581a7eec57e35b3a1636b8b0d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 55 D4 66 89 14 01 0F B6 45 D0 48 63 D0 48 89 D0 48 01 C0 48 }

	condition:
		all of them
}