rule ELASTIC_Linux_Cryptominer_Malxmr_70E5946E : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Malxmr (Linux.Cryptominer.Malxmr)"
		author = "Elastic Security"
		id = "70e5946e-3e73-4b07-9e7d-af036a3242f9"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Malxmr.yar#L240-L258"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2c2729395805fc9d3c1e654c9a065bbafc4f28d8ab235afaae8d2c484060596b"
		logic_hash = "324deafee2b14c125100e49b90ea95bc1fc55020a7e81a69c7730a57430560f4"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ced6885fda17c862753232fde3e7e8797f5a900ebab7570b78aa7138a0068eb9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 4F 70 48 8D B4 24 B0 00 00 00 48 89 34 CA 49 8B 57 68 48 89 C8 83 }

	condition:
		all of them
}