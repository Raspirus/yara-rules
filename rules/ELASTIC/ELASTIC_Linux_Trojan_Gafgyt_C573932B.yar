rule ELASTIC_Linux_Trojan_Gafgyt_C573932B : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "c573932b-9b3f-4ab7-a6b6-32dcc7473790"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L120-L138"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4c6aeaa6f6a0c40a3f4116a2e19e669188a8b1678a8930350889da1bab531c68"
		logic_hash = "174a3fcebc1e17cc35ddc11fde1798164b5783fc51fdf16581a9690c3b4d6549"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "18a3025ebb8af46605970ee8d7d18214854b86200001d576553e102cb71df266"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 83 7D 18 00 74 22 8B 45 1C 83 E0 02 85 C0 74 18 83 EC 08 6A 2D FF }

	condition:
		all of them
}