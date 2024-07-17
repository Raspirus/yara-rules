
rule ELASTIC_Linux_Cryptominer_Generic_102D6F7C : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "102d6f7c-0e77-4b23-9e84-756aba929d83"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L341-L359"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "bd40c2fbf775e3c8cb4de4a1c7c02bc4bcfa5b459855b2e5f1a8ab40f2fb1f9e"
		logic_hash = "52966eaaef5522e711dc89bd796b1e12019a8485ee789e8d5112d86f7e630170"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "037b1da31ffe66015c959af94d89eef2f7f846e1649e4415c31deaa81945aea9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 70 D2 AA C5 F9 EF D2 C5 F1 EF CB C5 E1 73 FB 04 C4 E3 79 DF }

	condition:
		all of them
}