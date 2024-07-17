rule ELASTIC_Windows_Generic_Threat_04A9C177 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "04a9c177-cacf-4509-b8dc-f30a628b7699"
		date = "2024-01-12"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1139-L1157"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0cccdde4dcc8916fb6399c181722eb0da2775d86146ce3cb3fc7f8cf6cd67c29"
		logic_hash = "ca7cf71228b1e13ec05c62cd9924ea5089fdf903d8ea4a5151866996ea81e01e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b36da73631711de0213658d30d3079f45449c303d8eb87b8342d1bd20120c7bb"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 6F 81 00 06 FE 3C A3 C3 D6 37 16 00 C2 87 21 EA 80 33 09 E5 00 2C 0F 24 BD 70 BC CB FB 00 94 5E 1B F8 14 F6 E6 95 07 01 CD 02 B0 D7 30 25 65 99 74 01 D6 A4 47 B3 20 AF 27 D8 11 7F 03 57 F6 37 }

	condition:
		all of them
}