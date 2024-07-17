rule ELASTIC_Linux_Cryptominer_Uwamson_D08B1D2E : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Uwamson (Linux.Cryptominer.Uwamson)"
		author = "Elastic Security"
		id = "d08b1d2e-cbd5-420e-8f36-22b9efb5f12c"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Uwamson.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4f7ad24b53b8e255710e4080d55f797564aa8c270bf100129bdbe52a29906b78"
		logic_hash = "8f489bb020397beae91f7bce82bc1b47912deab1b79224158f79c53f1d7c7fd3"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1e55dc81a44af9c15b7a803e72681b5c24030d34705219f83ca4779fd885098c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 4F F8 49 8D 7D 18 89 D9 49 83 C5 20 48 89 FE 41 83 E1 0F 4D 0F }

	condition:
		all of them
}