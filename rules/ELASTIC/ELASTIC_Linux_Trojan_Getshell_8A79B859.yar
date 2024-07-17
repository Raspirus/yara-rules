
rule ELASTIC_Linux_Trojan_Getshell_8A79B859 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Getshell (Linux.Trojan.Getshell)"
		author = "Elastic Security"
		id = "8a79b859-654c-4082-8cfc-61a143671457"
		date = "2021-06-28"
		modified = "2021-09-16"
		reference = "1154ba394176730e51c7c7094ff3274e9f68aaa2ed323040a94e1c6f7fb976a2"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Getshell.yar#L61-L79"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "2aa3914ec4cc04e5daa2da1460410b4f0e5e7a37c5a2eae5a02ff5f55382f1fe"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "5a95d1df94791c8484d783da975bec984fb11653d1f81f6397efd734a042272b"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 0A 00 89 E1 6A 1C 51 56 89 E1 43 6A 66 58 CD 80 B0 66 B3 04 }

	condition:
		all of them
}