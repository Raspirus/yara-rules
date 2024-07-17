rule ELASTIC_Linux_Cryptominer_Generic_18Af74B2 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "18af74b2-99fe-42fc-aacd-7887116530a8"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L421-L439"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "52707aa413c488693da32bf2705d4ac702af34faee3f605b207db55cdcc66318"
		logic_hash = "d8ec9bd01fcabdd4a80e07287ecc85026007672bbc3cd2d4cbb2aef98da88ed5"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "07a6b44ff1ba6143c76e7ccb3885bd04e968508e93c5f8bff9bc5efc42a16a96"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 00 70 6F 77 00 6C 6F 67 31 70 00 6C 6F 67 32 66 00 63 65 69 6C 00 }

	condition:
		all of them
}