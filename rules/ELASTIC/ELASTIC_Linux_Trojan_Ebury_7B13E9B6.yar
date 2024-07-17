rule ELASTIC_Linux_Trojan_Ebury_7B13E9B6 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Ebury (Linux.Trojan.Ebury)"
		author = "Elastic Security"
		id = "7b13e9b6-ce96-4bd3-8196-83420280bd1f"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Ebury.yar#L1-L18"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "30d126ffc5b782236663c23734f1eef21e1cc929d549a37bba8e1e7b41321111"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a891724ce36e86637540f722bc13b44984771f709219976168f12fe782f08306"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 8B 44 24 10 4C 8B 54 24 18 4C 8B 5C 24 20 8B 5C 24 28 74 04 }

	condition:
		all of them
}