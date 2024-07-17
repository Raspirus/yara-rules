
rule ELASTIC_Linux_Trojan_Generic_703A0258 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Generic (Linux.Trojan.Generic)"
		author = "Elastic Security"
		id = "703a0258-8d28-483e-a679-21d9ef1917b4"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Generic.yar#L61-L79"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b086d0119042fc960fe540c23d0a274dd0fb6f3570607823895c9158d4f75974"
		logic_hash = "cb37930637b8da91188d199ee20f1b64a0b1f13e966a99e69b983e623dac51de"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "796c2283eb14057081409800480b74ab684413f8f63a9db8704f5057026fb556"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { C2 F7 89 76 7E 86 87 F6 2B A3 2C 94 61 36 BE B6 }

	condition:
		all of them
}