rule ELASTIC_Linux_Cryptominer_Flystudio_0A370634 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Flystudio (Linux.Cryptominer.Flystudio)"
		author = "Elastic Security"
		id = "0a370634-51de-46bf-9397-c41ef08a7b83"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Flystudio.yar#L21-L38"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "cf924ba45a7dba19fe571bb9da8c4896690c3ad02f732b759a10174b9f61883f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "6613ddd986e2bf4b306cd1a5c28952da8068f1bb533c53557e2e2add5c2dbd1f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 72 D7 19 66 41 0F EF E9 66 0F EF EF 66 0F 6F FD 66 41 0F FE FD 66 44 0F }

	condition:
		all of them
}