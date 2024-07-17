rule ELASTIC_Linux_Trojan_Gafgyt_D2953F92 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "d2953f92-62ee-428d-88c5-723914c88c6e"
		date = "2021-06-28"
		modified = "2021-09-16"
		reference = "14cc92b99daa0c91aa09d9a7996ee5549a5cacd7be733960b2cf3681a7c2b628"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L1227-L1245"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "d0af462d26f6ffe469c57d63f1f7d551e3fb9cc39c7e4c35b3e71f659c01c076"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "276c6d62a8a335d0e2421b6b5b90c2c0eb69eec294bc9fcdeb7743abbf08d8bc"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 1B E5 2A 00 53 E3 0A 00 00 0A 30 30 1B E5 3F 00 53 E3 23 00 }

	condition:
		all of them
}