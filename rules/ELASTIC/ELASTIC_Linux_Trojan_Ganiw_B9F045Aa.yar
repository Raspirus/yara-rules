
rule ELASTIC_Linux_Trojan_Ganiw_B9F045Aa : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Ganiw (Linux.Trojan.Ganiw)"
		author = "Elastic Security"
		id = "b9f045aa-99fa-47e9-b179-ac62158b3fe2"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Ganiw.yar#L21-L38"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "2565101b261bee22ddecf6898ff0ac8a114d09c822d8db26ba3e3571ebe06b12"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0aaec92ca1c622df848bba80a2f1e4646252625d58e28269965b13d65158f238"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { E5 57 8B 55 0C 85 D2 74 21 FC 31 C0 8B 7D 08 AB AB AB AB AB AB }

	condition:
		all of them
}