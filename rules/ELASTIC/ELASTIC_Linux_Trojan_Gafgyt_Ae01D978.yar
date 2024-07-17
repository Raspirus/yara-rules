
rule ELASTIC_Linux_Trojan_Gafgyt_Ae01D978 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "ae01d978-d07d-4813-a22b-5d172c477d08"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L159-L176"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "c6c22b11dc1f0d4996e5da92c6edf58b7d21d7be40da87ddd39ed0e2d4c84072"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2d937c6009cfd53e11af52482a7418546ae87b047deabcebf3759e257cd89ce1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 00 00 2C 01 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D 04 9A }

	condition:
		all of them
}