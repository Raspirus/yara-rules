rule ELASTIC_Windows_Cryptominer_Generic_F53Cfb9B : FILE MEMORY
{
	meta:
		description = "Detects Windows Cryptominer Generic (Windows.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "f53cfb9b-0286-4e7e-895e-385b6f64c58a"
		date = "2024-03-05"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Cryptominer_Generic.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a9870a03ddc6543a5a12d50f95934ff49f26b60921096b2c8f2193cb411ed408"
		logic_hash = "b2453862747e251afc34c57e887889b8d3a65a9cc876d4a95ff5ecfcc24e4bd3"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2b66960ee7d423669d0d9e9dcd22ea6e1c0843893e5e04db92237b67b43d645c"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 48 81 EC B8 00 00 00 0F AE 9C 24 10 01 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0F AE 94 24 14 01 00 00 4C 8B A9 E0 00 00 00 4C 8B CA 4C 8B 51 20 4C 8B C1 4C 33 11 ?? ?? ?? ?? ?? ?? 4C 8B 59 28 }

	condition:
		all of them
}