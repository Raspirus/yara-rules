
rule ELASTIC_Linux_Trojan_Mirai_22965A6D : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "22965a6d-85d3-4f7c-be4a-581044581b77"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L140-L158"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "09c821aa8977f67878f8769f717c792d69436a951bb5ac06ce5052f46da80a48"
		logic_hash = "6b2a46694edf709d28267268252cfe95d88049b7dca854059cfe44479ada7423"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a34bcba23cde4a2a49ef8192fa2283ce03c75b2d1d08f1fea477932d4b9f5135"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { E6 4A 64 2B E4 82 D1 E3 F6 5E 88 34 DA 36 30 CE 4E 83 EC F1 }

	condition:
		all of them
}