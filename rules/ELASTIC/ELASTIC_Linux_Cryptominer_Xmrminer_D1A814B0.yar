
rule ELASTIC_Linux_Cryptominer_Xmrminer_D1A814B0 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Xmrminer (Linux.Cryptominer.Xmrminer)"
		author = "Elastic Security"
		id = "d1a814b0-38a6-4469-a29b-75787f52d789"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Xmrminer.yar#L179-L197"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "bea55bc9495ee51c78ceedadf3a685ea9d6dd428170888c67276c100d4d94beb"
		logic_hash = "a06f5d5be87153be1253c2e20a60fa36701a745813926be03ee466ce8e2285b0"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1746bc1d96207bd1bb44e9ff248b76245feb76c1d965400c3abd3b9116ea8455"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 01 48 8B 44 24 58 49 89 41 08 8B 01 48 C1 E0 05 4D 8D 04 07 48 8B 44 }

	condition:
		all of them
}