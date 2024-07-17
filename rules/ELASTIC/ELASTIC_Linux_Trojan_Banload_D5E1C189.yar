
rule ELASTIC_Linux_Trojan_Banload_D5E1C189 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Banload (Linux.Trojan.Banload)"
		author = "Elastic Security"
		id = "d5e1c189-7d19-4f03-a4f3-a0aaf6d499dc"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Banload.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "48bf0403f777db5da9c6a7eada17ad4ddf471bd73ea6cf02817dd202b49204f4"
		logic_hash = "3f0bee251152a8c835a3bf71dc33c2e150705713c50ca2cfdbeb69361ed91a09"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4aa04f08005b1b7ed941dbfc563737728099e35e3f0f025532921b91b79c967c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { E4 E4 E4 58 88 60 90 E4 E4 E4 E4 68 98 70 A0 E4 E4 E4 E4 78 }

	condition:
		all of them
}