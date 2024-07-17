rule ELASTIC_Linux_Trojan_Swrort_4Cb5B116 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Swrort (Linux.Trojan.Swrort)"
		author = "Elastic Security"
		id = "4cb5b116-5e90-4e5f-a62f-bfe616cab5db"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Swrort.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "703c16d4fcc6f815f540d50d8408ea00b4cf8060cc5f6f3ba21be047e32758e0"
		logic_hash = "9404856fc3290f3a8f9bf891fde9a614fc4484719eb3b51ce7ab601a41e0c3a5"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "cb783f69b4074264a75894dd85459529a172404a6901a1f5753a2f9197bfca58"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 6A 00 6A 00 6A 00 6A 00 6A 00 6A 00 6A 04 6A 10 89 E1 6A 00 }

	condition:
		all of them
}