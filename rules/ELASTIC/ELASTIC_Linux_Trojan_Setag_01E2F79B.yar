rule ELASTIC_Linux_Trojan_Setag_01E2F79B : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Setag (Linux.Trojan.Setag)"
		author = "Elastic Security"
		id = "01e2f79b-fcbc-41d0-a68b-3a692b893f26"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Setag.yar#L20-L38"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5b5e8486174026491341a750f6367959999bbacd3689215f59a62dbb13a45fcc"
		logic_hash = "1e0336760f364acbbe0e8aec10bc7bfb48ed7e33cde56d8914617664cb93fd9b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4ea87a6ccf907babdebbbb07b9bc32a5437d0213f1580ea4b4b3f44ce543a5bd"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 0C 8B 45 EC 89 45 FC 8D 55 E8 83 EC 04 8D 45 F8 50 8D 45 FC }

	condition:
		all of them
}