
rule ELASTIC_Linux_Trojan_Rbot_C69475E3 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Rbot (Linux.Trojan.Rbot)"
		author = "Elastic Security"
		id = "c69475e3-59eb-4d3c-9ee6-01ae7a3973d3"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Rbot.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "9d97c69b65d2900c39ca012fe0486e6a6abceebb890cbb6d2e091bb90f6b9690"
		logic_hash = "2a8629ebf6e2082ce90f1b2130ae596e4e515f3289a25899f2fc57b99c01a654"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "593ff388ba10d66b97b5dfc9220bbda6b1584fe73d6bf7c1aa0f5391bb87e939"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 56 8B 76 20 03 F5 33 C9 49 41 AD 33 DB 36 0F BE 14 28 38 F2 }

	condition:
		all of them
}