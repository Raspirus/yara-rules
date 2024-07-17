rule ELASTIC_Linux_Hacktool_Flooder_A9E8A90F : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Flooder (Linux.Hacktool.Flooder)"
		author = "Elastic Security"
		id = "a9e8a90f-5d95-4f4e-a9e0-c595be3729dd"
		date = "2021-06-28"
		modified = "2021-09-16"
		reference = "0558cf8cab0ba1515b3b69ac32975e5e18d754874e7a54d19098e7240ebf44e4"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Flooder.yar#L520-L538"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "8f1fcb736a9363142a25426ef2d166f92526bffaf8069f1b12056c9cf5825379"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a06bbcbc09e5e44447b458d302c47e4f18438be8d57687700cb4bf3f3630fba8"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 45 D8 48 89 45 F0 66 C7 45 EE 00 00 EB 19 48 8B 45 F0 48 8D }

	condition:
		all of them
}