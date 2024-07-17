
rule ELASTIC_Linux_Cryptominer_Xmrminer_D1Bb752F : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Xmrminer (Linux.Cryptominer.Xmrminer)"
		author = "Elastic Security"
		id = "d1bb752f-f5d6-4d93-96af-d977b501776a"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Xmrminer.yar#L100-L118"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "bea55bc9495ee51c78ceedadf3a685ea9d6dd428170888c67276c100d4d94beb"
		logic_hash = "47aa5516350d5c00d1387649df46ce8f09d87bdfafeaa4cbf1c3ef5f2e0b9023"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0f2455a4e80d93e7f1e420dc2f36e89c28ecb495879bca2e683a131b2770c3ee"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { F8 12 48 29 C8 48 2B 83 B0 00 00 00 48 C1 E8 03 48 F7 E2 48 8B }

	condition:
		all of them
}