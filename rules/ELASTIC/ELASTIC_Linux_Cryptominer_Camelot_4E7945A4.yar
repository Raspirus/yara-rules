
rule ELASTIC_Linux_Cryptominer_Camelot_4E7945A4 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Camelot (Linux.Cryptominer.Camelot)"
		author = "Elastic Security"
		id = "4e7945a4-b827-4496-89d8-e63c3141c773"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Camelot.yar#L79-L97"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b7504ce57787956e486d951b4ff78d73807fcc2a7958b172febc6d914e7a23a7"
		logic_hash = "aebc544076954fcce917e026467a8828b18446ce7c690b4c748562e311b7d491"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "bb2885705404c7d49491ab39fa8f50d85c354a43b4662b948c30635030feee74"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 89 E5 48 81 EC A0 00 00 00 48 89 7D F0 48 8B 7D F0 48 89 F8 48 05 80 00 }

	condition:
		all of them
}