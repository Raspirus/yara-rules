
rule ELASTIC_Linux_Trojan_Dofloo_Be1973Ed : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Dofloo (Linux.Trojan.Dofloo)"
		author = "Elastic Security"
		id = "be1973ed-a0ee-41ca-a752-fb5f990e2096"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Dofloo.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "88d826bac06c29e1b9024baaf90783e15d87d2a5c8c97426cbd5a70ae0f99461"
		logic_hash = "65f9daabf44006fe4405032bf93570185248bc62cd287650c68f854b23aa2158"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f032f072fd5da9ec4d8d3953bea0f2a236219b99ecfa67e3fac44f2e73f33e9c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { A8 8B 45 A8 89 45 A4 83 7D A4 00 79 04 83 45 A4 03 8B 45 A4 C1 }

	condition:
		all of them
}