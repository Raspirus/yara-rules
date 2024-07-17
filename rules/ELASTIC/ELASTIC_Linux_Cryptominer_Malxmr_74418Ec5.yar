
rule ELASTIC_Linux_Cryptominer_Malxmr_74418Ec5 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Malxmr (Linux.Cryptominer.Malxmr)"
		author = "Elastic Security"
		id = "74418ec5-f84a-4d79-b1b0-c1d579ad7b97"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Malxmr.yar#L161-L179"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d79ad967ac9fc0b1b6d54e844de60d7ba3eaad673ee69d30f9f804e5ccbf2880"
		logic_hash = "e74463f53611baaec7c8e126218d8353c6e3a5e71c20e98a7035df6b771b690b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ec14cac86b2b0f75f1d01b7fb4b57bfa3365f8e4d11bfed2707b0174875d1234"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { F9 75 7A A8 8A 65 FC 5C E0 6E 09 4B 8F AA B3 A4 66 44 B1 D1 13 }

	condition:
		all of them
}