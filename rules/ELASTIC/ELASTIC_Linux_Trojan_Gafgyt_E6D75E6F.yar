
rule ELASTIC_Linux_Trojan_Gafgyt_E6D75E6F : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "e6d75e6f-aa04-4767-8730-6909958044a7"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L732-L750"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "48b15093f33c18778724c48c34199a420be4beb0d794e36034097806e1521eb8"
		logic_hash = "339dd33a3313a4a94d2515cd4c2100ac6b9d5e0029881494c28dc3e7c8a05798"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e99805e8917d6526031270b6da5c2f3cc1c8235fed1d47134835a107d0df497c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 00 00 00 CD 80 C3 8B 54 24 04 8B 4C 24 08 87 D3 B8 5B 00 00 00 }

	condition:
		all of them
}