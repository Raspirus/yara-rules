
rule ELASTIC_Linux_Trojan_Gognt_05B10F4B : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gognt (Linux.Trojan.Gognt)"
		author = "Elastic Security"
		id = "05b10f4b-7434-457a-9e8e-d898bb839dce"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gognt.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e43aaf2345dbb5c303d5a5e53cd2e2e84338d12f69ad809865f20fd1a5c2716f"
		logic_hash = "1dfc3417f75aa81aea5eda3d6da076f1cacf82dbfc039252b1d16f52b81a5a65"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "fdf7b65f812c17c7f30b3095f237173475cdfb0c10a4b187f751c0599f6b5729"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 7C 24 78 4C 89 84 24 A8 00 00 00 48 29 D7 49 89 F9 48 F7 DF 48 C1 }

	condition:
		all of them
}