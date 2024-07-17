rule ELASTIC_Linux_Cryptominer_Uwamson_0797De34 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Uwamson (Linux.Cryptominer.Uwamson)"
		author = "Elastic Security"
		id = "0797de34-9181-4f28-a4b0-eafa67e20b41"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Uwamson.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e4699e35ce8091f97decbeebff63d7fa8c868172a79f9d9d52b6778c3faab8f2"
		logic_hash = "7ab5dd99d8bbef61ec764900df5bebf39ed90833a8f9481c427cbb46faf2c521"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b6a210c23f09ffa0114f12aa741be50f234b8798a3275ac300aa17da29b8727c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 43 20 48 B9 AB AA AA AA AA AA AA AA 88 44 24 30 8B 43 24 89 44 }

	condition:
		all of them
}