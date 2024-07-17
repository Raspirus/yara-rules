
rule ELASTIC_Linux_Cryptominer_Camelot_6A279F19 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Camelot (Linux.Cryptominer.Camelot)"
		author = "Elastic Security"
		id = "6a279f19-3c9e-424b-b89e-8807f40b89eb"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Camelot.yar#L59-L77"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5b01f72b2c53db9b8f253bb98c6584581ebd1af1b1aaee62659f54193c269fca"
		logic_hash = "91e3c0d96fe5ab9c61b38f01d39639020ec459bec6348b1f87a2c5b1a874e24a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1c0ead7a7f7232edab86d2ef023c853332254ce1dffe1556c821605c0a83d826"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 89 F3 89 D6 48 83 EC 30 48 89 E2 64 48 8B 04 25 28 00 00 00 48 89 44 }

	condition:
		all of them
}