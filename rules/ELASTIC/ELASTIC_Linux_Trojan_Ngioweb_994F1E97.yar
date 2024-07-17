rule ELASTIC_Linux_Trojan_Ngioweb_994F1E97 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Ngioweb (Linux.Trojan.Ngioweb)"
		author = "Elastic Security"
		id = "994f1e97-c370-4eb2-ac93-b5ebf112f55d"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Ngioweb.yar#L161-L178"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "2384e787877b622445d7d14053a8340d2e97d3ab103a3fabfa08a40068726ad0"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "6cc0ace6beb6c1bf4e10f9781bb551c10f48cc23efe9529d92b432b0ff88f245"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { C6 44 24 16 68 C6 44 24 15 63 C6 44 24 14 74 C6 44 24 13 61 C6 44 24 12 77 C6 44 24 11 2F C6 44 24 10 76 C6 44 24 0F 65 C6 44 24 0E 64 C6 44 24 0D 2F }

	condition:
		all of them
}