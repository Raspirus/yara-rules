rule ELASTIC_Linux_Cryptominer_Malxmr_D13544D7 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Malxmr (Linux.Cryptominer.Malxmr)"
		author = "Elastic Security"
		id = "d13544d7-4834-4ce7-9339-9c933ee51b2c"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Malxmr.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "85fa30ba59602199fd99463acf50bd607e755c2e18cd8843ffcfb6b1aca24bb3"
		logic_hash = "fcb2fc7a84fbcd23f9a9d9fd2750c45ff881689670a373fce0cc444183d11999"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "02e1be4a7073e849b183851994c83f1f2077fe74cbcdd0b3066999d0c9499a09"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 51 50 4D 21 EB 4B 8D 0C 24 4C 89 54 24 90 4C 89 DD 48 BA AA AA AA AA AA AA }

	condition:
		all of them
}