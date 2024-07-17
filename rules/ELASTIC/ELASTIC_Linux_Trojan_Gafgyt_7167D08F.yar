
rule ELASTIC_Linux_Trojan_Gafgyt_7167D08F : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "7167d08f-bfeb-4d78-9783-3a1df2ef0ed3"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L752-L770"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4c6aeaa6f6a0c40a3f4116a2e19e669188a8b1678a8930350889da1bab531c68"
		logic_hash = "88c07bf06801192f38ef66229a0aa5c1ef6242caeb080ce1c7cd13ad0d540c82"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b9df4ab322a2a329168f684b07b7b05ee3d03165c5b9050a4710eae7aeca6cd9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 0C 8A 00 3C 2D 75 13 FF 45 0C C7 45 E4 01 00 00 00 EB 07 FF }

	condition:
		all of them
}