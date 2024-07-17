rule ELASTIC_Linux_Cryptominer_Malxmr_C8Adb449 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Malxmr (Linux.Cryptominer.Malxmr)"
		author = "Elastic Security"
		id = "c8adb449-3de5-4cdd-9b62-fe4bcbe82394"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Malxmr.yar#L101-L119"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "00ec7a6e9611b5c0e26c148ae5ebfedc57cf52b21e93c2fe3eac85bf88edc7ea"
		logic_hash = "9c43602dc752dd737a983874bee5ec6af145ce5fdd45d03864a1afdc2aec3ad4"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "838950826835e811eb7ea3af7a612b4263d171ded4761d2b547a4012adba4028"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { D2 4C 89 54 24 A0 4C 89 FA 48 F7 D2 48 23 54 24 88 49 89 D2 48 8B 54 }

	condition:
		all of them
}