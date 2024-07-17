
rule ELASTIC_Linux_Cryptominer_Generic_D81368A3 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "d81368a3-00ca-44cf-b009-718272d389eb"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L221-L239"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "71225e4702f2e0a0ecf79f7ec6c6a1efc95caf665fda93a646519f6f5744990b"
		logic_hash = "0e30c9ebd8f2d3a489180f114daf91a3655ce9075ae25ea3d6ef5be472d7721a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "dd463df2c03389af3e7723fda684b0f42342817b3a76664d131cf03542837b8a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { CB 49 C1 E3 04 49 01 FB 41 8B 13 39 D1 7F 3F 7C 06 4D 3B 43 08 }

	condition:
		all of them
}