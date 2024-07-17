rule ELASTIC_Linux_Trojan_Mobidash_52A15A93 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mobidash (Linux.Trojan.Mobidash)"
		author = "Elastic Security"
		id = "52a15a93-0574-44bb-83c9-793558432553"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mobidash.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "6694640e7df5308a969ef40f86393a65febe51639069cb7eaa5650f62c1f4083"
		logic_hash = "ceaf5b06108baa6043e31010d777099ed6ac9b4054e86d41309bd7c2b0ffda11"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a7ceff3bbd61929ab000d18ffdf2e8d1753ecea123e26cd626e3af64341effe6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 41 89 CE 41 55 41 54 49 89 F4 55 48 89 D5 53 48 89 FB 48 8B 07 FF 90 F8 00 }

	condition:
		all of them
}