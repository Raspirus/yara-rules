
rule ELASTIC_Linux_Trojan_Badbee_231Cb054 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Badbee (Linux.Trojan.Badbee)"
		author = "Elastic Security"
		id = "231cb054-36a9-434f-8254-17fee38e5275"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Badbee.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "832ba859c3030e58b94398ff663ddfe27078946a83dcfc81a5ef88351d41f4e2"
		logic_hash = "a1ed8f2da9b4f891a5c65d943424bb7c465f0d07e7756e292c617ce5ef14d182"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ebe789fc467daf9276f72210f94e87b7fa79fc92a72740de49e47b71f123ed5c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 8D B4 41 31 44 97 10 83 F9 10 75 E4 89 DE C1 FE 14 F7 C6 01 00 }

	condition:
		all of them
}