
rule ELASTIC_Linux_Trojan_Backconnect_C6803B39 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Backconnect (Linux.Trojan.Backconnect)"
		author = "Elastic Security"
		id = "c6803b39-e2e0-4ab8-9ead-e53eab26bb53"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Backconnect.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a5e6b084cdabe9a4557b5ff8b2313db6c3bb4ba424d107474024030115eeaa0f"
		logic_hash = "02750b2788c2912bba0fc8594f6a12c75ce1f41d1075acf7c920f6e616ab65c7"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1dfb097c90b0cf008dc9d3ae624e08504755222f68ee23ed98d0fa8803cff91a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 78 3A 48 98 48 01 C3 49 01 C5 48 83 FB 33 76 DC 31 C9 BA 10 00 }

	condition:
		all of them
}