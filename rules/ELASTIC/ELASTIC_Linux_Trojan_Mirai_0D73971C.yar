rule ELASTIC_Linux_Trojan_Mirai_0D73971C : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "0d73971c-4253-4e7d-b1e1-20b031197f9e"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1184-L1202"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "49c94d184d7e387c3efe34ae6f021e011c3046ae631c9733ab0a230d5fe28ead"
		logic_hash = "56f3bac05fce0a0458e5b80197335e7bef6dcd50b9feb6f1008b8679f29cf37a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "95279bc45936ca867efb30040354c8ff81de31dccda051cfd40b4fb268c228c5"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 89 C2 83 EB 04 C1 E2 0B 31 C2 89 F0 C1 E8 13 89 D1 31 F0 C1 }

	condition:
		all of them
}