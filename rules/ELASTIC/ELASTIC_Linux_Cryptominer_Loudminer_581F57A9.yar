
rule ELASTIC_Linux_Cryptominer_Loudminer_581F57A9 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Loudminer (Linux.Cryptominer.Loudminer)"
		author = "Elastic Security"
		id = "581f57a9-36e0-4b95-9a1e-837bdd4aceab"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Loudminer.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2c2729395805fc9d3c1e654c9a065bbafc4f28d8ab235afaae8d2c484060596b"
		logic_hash = "82db0985f215da1d84e16fce94df7553b43b06082bf5475515dbbcf016c40fe4"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1013e6e11ea2a30ecf9226ea2618a59fb08588cdc893053430e969fbdf6eb675"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 44 24 08 48 8B 70 20 48 8B 3B 48 83 C3 08 48 89 EA 48 8B 07 FF }

	condition:
		all of them
}