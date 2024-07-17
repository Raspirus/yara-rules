
rule ELASTIC_Linux_Hacktool_Tcpscan_334D0Ca5 : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Tcpscan (Linux.Hacktool.Tcpscan)"
		author = "Elastic Security"
		id = "334d0ca5-d143-4a32-8632-9fbdd2d96987"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Tcpscan.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "62de04185c2e3c22af349479a68ad53c31b3874794e7c4f0f33e8d125c37f6b0"
		logic_hash = "94ee723c660294e35caec5a2b66eeea64896265cfebc839ed3f55cf8f8c67d7e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1f8fc064770bd76577b9455ae858d8a98b573e01a199adf2928d8433d990eaa7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { C4 10 89 45 D4 83 7D D4 00 79 1A 83 EC 0C 68 13 }

	condition:
		all of them
}