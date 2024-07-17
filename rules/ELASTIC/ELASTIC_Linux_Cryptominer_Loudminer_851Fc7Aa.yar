rule ELASTIC_Linux_Cryptominer_Loudminer_851Fc7Aa : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Loudminer (Linux.Cryptominer.Loudminer)"
		author = "Elastic Security"
		id = "851fc7aa-6514-4f47-b6b5-a1e730b5d460"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Loudminer.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2c2729395805fc9d3c1e654c9a065bbafc4f28d8ab235afaae8d2c484060596b"
		logic_hash = "9f271a16fe30fbf0c16533522b733228f19e0c44d173e4c0ef43bf13323e7383"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e4d78229c1877a023802d7d99eca48bffc55d986af436c8a1df7c6c4e5e435ba"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 49 8B 45 00 4C 8B 40 08 49 8D 78 18 49 89 FA 49 29 D2 49 01 C2 4C }

	condition:
		all of them
}