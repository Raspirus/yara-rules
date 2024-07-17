rule ELASTIC_Linux_Cryptominer_Presenoker_3Bb5533D : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Presenoker (Linux.Cryptominer.Presenoker)"
		author = "Elastic Security"
		id = "3bb5533d-4722-4801-9fbb-dd2c916cffc6"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Presenoker.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "bbc155c610c7aa439f98e32f97895d7eeaef06dab7cca05a5179b0eb3ba3cc00"
		logic_hash = "13bf69ea6bc7df5ba9ebffe67234657f2ecab99e28fd76d0bbedceaf9706a4dd"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a3005a07901953ae8def7bd9d9ec96874da0a8aedbebde536504abed9d4191fd"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 47 10 74 72 F3 0F 6F 00 66 0F 7E C2 0F 29 04 24 85 D2 F3 0F 6F }

	condition:
		all of them
}