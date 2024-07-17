
rule ELASTIC_Linux_Trojan_Mirai_Aa39Fb02 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "aa39fb02-ca7e-4809-ab5d-00e92763f7ec"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L989-L1006"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "ffa95d92a2b619008bd5918cd34a17cd034b2830dc09d495db4b0c397b1cb53a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b136ba6496816ba9737a3eb0e633c28a337511a97505f06e52f37b38599587cb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 74 DE 8D 40 F1 3C 01 76 D7 80 FA 38 74 D2 80 FA 0A 74 CD 80 }

	condition:
		all of them
}