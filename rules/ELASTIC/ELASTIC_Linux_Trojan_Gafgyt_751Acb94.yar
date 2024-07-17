
rule ELASTIC_Linux_Trojan_Gafgyt_751Acb94 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "751acb94-cb23-4949-a4dd-87985c47379e"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L693-L710"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "1963351d209168f4ae2268d245cfd5320e4442d00746d021088ffae98e5da454"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "dbdfdb455868332e9fbadd36c084d0927a3dd8ab844f0b1866e914914084cd4b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 20 54 6F 20 43 6F 6E 6E 65 63 74 21 20 00 53 75 63 63 65 73 66 }

	condition:
		all of them
}