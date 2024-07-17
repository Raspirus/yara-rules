
rule ELASTIC_Linux_Cryptominer_Xmrig_57C0C6D7 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Xmrig (Linux.Cryptominer.Xmrig)"
		author = "Elastic Security"
		id = "57c0c6d7-ded1-4a3e-9877-4003ab46d4a6"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Xmrig.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "100dc1ede4c0832a729d77725784d9deb358b3a768dfaf7ff9e96535f5b5a361"
		logic_hash = "d3a272d488cebe4f774c994001a14d825372a27f16267bc0339b7e3b22ada8db"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b36ef33a052cdbda0db0048fc9da4ae4b4208c0fa944bc9322f029d4dfef35b8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 78 01 66 0F EF C9 49 89 38 0F BE 00 83 E8 30 F2 0F 2A C8 48 }

	condition:
		all of them
}