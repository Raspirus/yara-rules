
rule ELASTIC_Linux_Cryptominer_Ccminer_3C593Bc3 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Ccminer (Linux.Cryptominer.Ccminer)"
		author = "Elastic Security"
		id = "3c593bc3-cb67-41da-bef1-aad9e73c34f7"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Ccminer.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "dbb403a00c75ef2a74b41b8b58d08a6749f37f922de6cc19127a8f244d901c60"
		logic_hash = "94a0d33b474b3c60e926eaf06147eb0fdc56beac525f25326448bf2a5177d9c0"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0a382ef73d3b5d1b1ad223c66fc367cc5b6f2b23a9758002045076234f257dfe"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 20 83 5C DE C2 00 00 00 68 03 5C EB EA 00 00 00 48 03 1C DC }

	condition:
		all of them
}