rule ELASTIC_Linux_Trojan_Xorddos_2Aef46A6 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Xorddos (Linux.Trojan.Xorddos)"
		author = "Elastic Security"
		id = "2aef46a6-6daf-4f02-b1b4-e512cea12e53"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Xorddos.yar#L1-L18"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "d2c88774eb5227cf2d133644c648ebe5ba40c7e0acb2b432bc6a1a9da10bfb3f"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "e583729c686b80e5da8e828a846cbd5218a4d787eff1fb2ce84a775ad67a1c4d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 25 64 2D 2D 25 73 5F 25 64 3A 25 73 }

	condition:
		all of them
}