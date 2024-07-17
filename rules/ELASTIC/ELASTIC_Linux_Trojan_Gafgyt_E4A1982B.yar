
rule ELASTIC_Linux_Trojan_Gafgyt_E4A1982B : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "e4a1982b-928a-4da5-b497-cedc1d26e845"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L1011-L1028"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "4cd7aa205b3571cffca208e315d6311fa92a5993e2a8e40d342d6184811f42f0"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "d9f852c28433128b0fd330bee35f7bd4aada5226e9ca865fe5cd8cca52b2a622"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 8B 45 EC F7 D0 21 D0 33 45 FC C9 C3 55 48 89 E5 48 83 EC 30 48 89 }

	condition:
		all of them
}