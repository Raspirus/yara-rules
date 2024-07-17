rule ELASTIC_Linux_Trojan_Gafgyt_09C3070E : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "09c3070e-4b71-45a0-aa62-0cc6e496644a"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L514-L532"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "275cbd5d3b3d8c521649b95122d90d1ca9b7ae1958b721bdc158aaa2d31d49df"
		logic_hash = "f8f8e8883cf1e51fbaef81b8334ac5fa45a54682d285282da62c80e4aa50a48d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "84fad96b60b297736c149e14de12671ff778bff427ab7684df2c541a6f6d7e7d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 48 C1 E8 06 48 89 C6 48 8B 94 C5 50 FF FF FF 8B 8D 2C FF FF FF 83 }

	condition:
		all of them
}