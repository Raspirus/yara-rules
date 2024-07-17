rule ELASTIC_Linux_Cryptominer_Generic_5E56D076 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "5e56d076-0d6d-4979-8ebc-52607dcdb42d"
		date = "2022-01-05"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L781-L799"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "32e1cb0369803f817a0c61f25ca410774b4f37882cab966133b4f3e9c74fac09"
		logic_hash = "c8e2ebcffe8a169c2cc311c95538b674937fa87e06d2946a6ed3b0c1f039f7fc"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e9ca9b9faee091afed534b89313d644a52476b4757663e1cdfbcbca379857740"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 71 18 4C 89 FF FF D0 48 8B 84 24 A0 00 00 00 48 89 43 60 48 8B 84 24 98 00 }

	condition:
		all of them
}