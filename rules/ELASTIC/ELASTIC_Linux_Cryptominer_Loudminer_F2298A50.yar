rule ELASTIC_Linux_Cryptominer_Loudminer_F2298A50 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Loudminer (Linux.Cryptominer.Loudminer)"
		author = "Elastic Security"
		id = "f2298a50-7bd4-43d8-ac84-b36489405f2e"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Loudminer.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2c2729395805fc9d3c1e654c9a065bbafc4f28d8ab235afaae8d2c484060596b"
		logic_hash = "6c2c9b6aea1fb35f8f600dd084ed9cfd56123f7502036e76dd168ccd8b43b28f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8eafc1c995c0efb81d9ce6bcc107b102551371f3fb8efdf8261ce32631947e03"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { B6 04 07 41 8D 40 D0 3C 09 76 AD 41 8D 40 9F 3C 05 76 A1 41 8D }

	condition:
		all of them
}