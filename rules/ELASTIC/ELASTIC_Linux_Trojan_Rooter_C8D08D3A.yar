
rule ELASTIC_Linux_Trojan_Rooter_C8D08D3A : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Rooter (Linux.Trojan.Rooter)"
		author = "Elastic Security"
		id = "c8d08d3a-ff9c-4545-9f09-45fbe5b534f3"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Rooter.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f55e3aa4d875d8322cdd7caa17aa56e620473fe73c9b5ae0e18da5fbc602a6ba"
		logic_hash = "c91f3112cc61acec08ab3cd59bab2ae833ba0d8ac565ffb26a46982f38af0e71"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2a09f9fabfefcf44c71ee17b823396991940bedd7a481198683ee3e88979edf4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { D8 DC 04 08 BB 44 C3 04 08 CD 80 C7 05 48 FB 04 }

	condition:
		all of them
}