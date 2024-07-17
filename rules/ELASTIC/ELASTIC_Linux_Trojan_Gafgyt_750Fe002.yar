
rule ELASTIC_Linux_Trojan_Gafgyt_750Fe002 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "750fe002-cac1-4832-94d2-212aa5ec17e3"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L376-L394"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4c6aeaa6f6a0c40a3f4116a2e19e669188a8b1678a8930350889da1bab531c68"
		logic_hash = "eb9907d8a63822c2e3ab57d43dca8ede7876610f029e2f9c10c9eeace9ea0078"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f51347158a6477b0da4ed4df3374fbad92b6ac137aa4775f83035d1e30cba7dc"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 10 8B 45 0C 40 8A 00 3C FC 75 06 C6 45 FF FE EB 50 8B 45 0C 40 }

	condition:
		all of them
}