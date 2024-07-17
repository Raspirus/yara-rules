
rule ELASTIC_Linux_Cryptominer_Pgminer_5Fb2Efd5 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Pgminer (Linux.Cryptominer.Pgminer)"
		author = "Elastic Security"
		id = "5fb2efd5-4adc-4285-bef1-6e4987066944"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Pgminer.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "6d296648fdbc693e604f6375eaf7e28b87a73b8405dc8cd3147663b5e8b96ff0"
		logic_hash = "4c247f40c9781332f04f82a244f6e8e22c9c744963f736937eddecf769b40a54"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8ac56b60418e3f3f4d1f52c7a58d0b7c1f374611d45e560452c75a01c092a59b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 00 16 00 00 00 0E 00 00 00 18 03 00 7F EB 28 33 C5 56 5D F2 50 67 C5 6F }

	condition:
		all of them
}