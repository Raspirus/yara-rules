
rule ELASTIC_Linux_Trojan_Kaiji_91091Be3 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Kaiji (Linux.Trojan.Kaiji)"
		author = "Elastic Security"
		id = "91091be3-8c9e-4d7a-8ca6-cd422afe0aa5"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Kaiji.yar#L61-L79"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "dca574d13fcbd7d244d434fcbca68136e0097fefc5f131bec36e329448f9a202"
		logic_hash = "3b55cb3be5775311af4dc90f9624448d30cc58ef1a42729f6ca4eb3b36ad8b06"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f583bbef07f41e74ba9646a3e97ef114eb34b1ae820ed499dffaad90db227ca6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 24 18 83 7C 24 1C 02 75 9E 8B 4C 24 64 8B 51 1C 89 54 24 5C }

	condition:
		all of them
}