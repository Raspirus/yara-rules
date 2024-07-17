rule ELASTIC_Macos_Trojan_Adload_F6B18A0A : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Adload (MacOS.Trojan.Adload)"
		author = "Elastic Security"
		id = "f6b18a0a-7593-430f-904b-8d416861d165"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Adload.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "06f38bb811e6a6c38b5e2db708d4063f4aea27fcd193d57c60594f25a86488c8"
		logic_hash = "20d43fbf0b8155940e2e181f376a7b1979ce248d88dc08409aaa1a916777231c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f33275481b0bf4f4e57c7ad757f1e22d35742fc3d0ffa3983321f03170b5100e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 10 49 8B 4E 20 48 BE 89 88 88 88 88 88 88 88 48 89 C8 48 F7 E6 49 39 DC 0F 84 }

	condition:
		all of them
}