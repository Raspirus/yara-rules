rule ELASTIC_Linux_Cryptominer_Generic_B9E6Ffdf : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "b9e6ffdf-4b2b-4052-9c91-a06f43a2e7b8"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L601-L619"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c0f3200a93f1be4589eec562c4f688e379e687d09c03d1d8850cc4b5f90f192a"
		logic_hash = "57d5b3eb5812a849d04695bdb1fb728a5ebd3bf5201ac3e7f36d37af0622eec2"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "fdd91d5802d5807d52f4c9635e325fc0765bb54cf51305c7477d2b791f393f3e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 89 D8 48 83 C4 20 5B C3 0F 1F 00 BF ?? ?? 40 00 }

	condition:
		all of them
}