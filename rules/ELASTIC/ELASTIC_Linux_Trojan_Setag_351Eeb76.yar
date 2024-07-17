rule ELASTIC_Linux_Trojan_Setag_351Eeb76 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Setag (Linux.Trojan.Setag)"
		author = "Elastic Security"
		id = "351eeb76-ccca-40d5-8ee3-e8daf6494dda"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Setag.yar#L1-L18"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "3519d9e4bfa18c19b49d0fa15ef78151bd13db9614406c4569720d20830f3cbb"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c6edc7ae898831e9cc3c92fcdce4cd5b4412de061575e6da2f4e07776e0885f5"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 04 8B 45 F8 C1 E0 02 01 C2 8B 45 EC 89 02 8D 45 F8 FF 00 8B }

	condition:
		all of them
}