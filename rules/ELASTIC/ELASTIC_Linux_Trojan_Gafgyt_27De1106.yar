
rule ELASTIC_Linux_Trojan_Gafgyt_27De1106 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "27de1106-497d-40a0-8fc4-929f7a927628"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L772-L790"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "899c072730590003b98278bdda21c15ecaa2f49ad51e417ed59e88caf054a72d"
		logic_hash = "4e266e1ae31d7d86866b112a04ca38c0a8185c18ebb10ac6497bbaa69f51b2fd"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "9a747f0fc7ccc55f24f2654344484f643103da709270a45de4c1174d8e4101cc"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 0C 0F B6 00 84 C0 74 18 8B 45 0C 40 8B 55 08 42 89 44 24 04 89 }

	condition:
		all of them
}