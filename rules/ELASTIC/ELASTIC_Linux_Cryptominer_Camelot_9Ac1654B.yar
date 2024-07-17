
rule ELASTIC_Linux_Cryptominer_Camelot_9Ac1654B : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Camelot (Linux.Cryptominer.Camelot)"
		author = "Elastic Security"
		id = "9ac1654b-f2f0-4d32-8e2a-be30b3e61bb0"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Camelot.yar#L1-L18"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "5de1f43803f3d3b94149ea39ed961e7b9a1ad86c15c5085e2e0a5f9c314e98ff"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "156c60ee17e9b39cb231d5f0703b6e2a7e18247484f35e11d3756a025873c954"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { CD 41 C1 CC 0B 31 D1 31 E9 44 89 D5 44 31 CD C1 C9 07 41 89 E8 }

	condition:
		all of them
}