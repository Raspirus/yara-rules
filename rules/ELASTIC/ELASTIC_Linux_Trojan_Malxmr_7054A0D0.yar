rule ELASTIC_Linux_Trojan_Malxmr_7054A0D0 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Malxmr (Linux.Trojan.Malxmr)"
		author = "Elastic Security"
		id = "7054a0d0-11d4-4671-a88d-ea933e73fe11"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Malxmr.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "3a6b3552ffac13aa70e24fef72b69f683ac221105415efb294fb9a2fc81c260a"
		logic_hash = "f7153fb11e0e4bf422021cc0fab99536c2a193198bf70d7f2af2fa5c1971c028"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "9661cc2b7a1d7b882ca39307adc927f5fb73d59f3771a8b456c2cf2ff3d801e9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 6E 64 47 56 7A 64 48 52 6C 63 33 52 30 5A 58 4E 30 64 47 56 }

	condition:
		all of them
}