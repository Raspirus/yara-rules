rule ELASTIC_Linux_Cryptominer_Generic_B4C2D007 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "b4c2d007-9464-4b72-ae2d-b0f1aeaa6fca"
		date = "2024-04-19"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L901-L919"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e1e518ba226d30869e404b92bfa810bae27c8b1476766934961e80c44e39c738"
		logic_hash = "cb52d9233028918210b8bd3959a6649d75b5c6873befff0cf62d9e71dfecc302"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "364fa077b99cd32d790399fd9f06f99ffef19c37487ef8a4fd81bf36988ecaa6"
		severity = 100
		arch_context = "x86, arm64"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { FD 03 00 91 F3 53 01 A9 F4 03 00 AA 20 74 40 F9 60 17 00 B4 20 10 42 79 F3 03 01 AA F9 6B 04 A9 40 17 00 34 62 62 40 39 F5 5B 02 A9 26 10 40 39 F7 63 03 A9 63 12 40 B9 FB 73 05 A9 3B A0 03 91 }

	condition:
		all of them
}