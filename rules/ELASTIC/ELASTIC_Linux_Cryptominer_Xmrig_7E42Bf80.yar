
rule ELASTIC_Linux_Cryptominer_Xmrig_7E42Bf80 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Xmrig (Linux.Cryptominer.Xmrig)"
		author = "Elastic Security"
		id = "7e42bf80-60a4-4d45-bf07-b96a188c6e6b"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Xmrig.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "551b6e6617fa3f438ec1b3bd558b3cbc981141904cab261c0ac082a697e5b07d"
		logic_hash = "ad8c8f0081d07f7e2a5400de6af2c6b311f77ff336d7576f7fb0bfe2593a9062"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "cf3b74ae6ff38b0131763fbcf65fa21fb6fd4462d2571b298c77a43184ac5415"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 0F 70 F8 FF 66 0F 73 FD 04 66 44 0F EF ED 66 41 0F 73 FE 04 66 41 0F }

	condition:
		all of them
}