
rule ELASTIC_Linux_Cryptominer_Uwamson_41E36585 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Uwamson (Linux.Cryptominer.Uwamson)"
		author = "Elastic Security"
		id = "41e36585-0ef1-4896-a887-dac437c716a5"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Uwamson.yar#L61-L79"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "8cfc38db2b860efcce5da40ce1e3992f467ab0b7491639d68d530b79529cda80"
		logic_hash = "e176523afe8c3394ddda41a5ef11f825fed1e149476709a7c1ea26b8af72d4fc"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ad2d4a46b9378c09b1aef0f2bf67a990b3bacaba65a5b8c55c2edb0c9a63470d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { F8 03 48 C1 FF 03 4F 8D 44 40 FD 48 0F AF FE 49 01 F8 4C 01 C2 4C }

	condition:
		all of them
}