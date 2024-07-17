
rule ELASTIC_Linux_Trojan_Pnscan_20E34E35 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Pnscan (Linux.Trojan.Pnscan)"
		author = "Elastic Security"
		id = "20e34e35-8639-4a0d-bfe3-6bfa1570f14d"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Pnscan.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "7dbd5b709f16296ba7dac66dc35b9c3373cf88452396d79d0c92d7502c1b0005"
		logic_hash = "1e69ef50d25ffd0f38ed0eb81ab3295822aa183c5e06f307caf02826b1dfa011"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "07678bd23ae697d42e2c7337675f7a50034b10ec7a749a8802820904a943641a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 4C 00 54 45 4C 20 3A 20 00 3C 49 41 43 3E 00 3C 44 4F 4E 54 3E 00 }

	condition:
		all of them
}