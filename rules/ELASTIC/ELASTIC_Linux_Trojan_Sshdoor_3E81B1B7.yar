rule ELASTIC_Linux_Trojan_Sshdoor_3E81B1B7 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Sshdoor (Linux.Trojan.Sshdoor)"
		author = "Elastic Security"
		id = "3e81b1b7-71bd-4876-a616-ca49ce73c2da"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Sshdoor.yar#L81-L99"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "def4de838d58c70f9f0ae026cdad3bf09b711a55af97ed20804fa1e34e7b59e9"
		logic_hash = "54253df560e6552a728dc2651c557bc23ae8ec4847760290701438821c52342e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7849bb7283adb25c2ee492efd8d9b2c63de7ae701a69e1892cdc25175996b227"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 24 24 48 89 E7 C1 EE 05 83 E6 01 FF D3 8B 54 24 28 31 C0 BE 5A 00 }

	condition:
		all of them
}