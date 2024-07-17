rule ELASTIC_Linux_Cryptominer_Generic_4E9075E6 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "4e9075e6-3ca9-459e-9f5f-3e614fd4f1c8"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L561-L579"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "098bf2f1ce9d7f125e1c9618f349ae798a987316e95345c037a744964277f0fe"
		logic_hash = "fe117f65666b9eac19fa588ee631f9be7551a3a9e3695b7ecbb77806658678aa"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "70d8c4ecb185b8817558ad9d26a47c340c977abb6abfca8efe1ff99efb43c579"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 2C 24 74 67 48 89 5C 24 18 4C 89 6C 24 20 4C 89 FB 4D 89 E5 4C 8B }

	condition:
		all of them
}