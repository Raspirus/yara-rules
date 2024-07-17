
rule ELASTIC_Linux_Hacktool_Prochide_7333221A : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Prochide (Linux.Hacktool.Prochide)"
		author = "Elastic Security"
		id = "7333221a-b3dc-4b26-8ec7-7e4f5405e228"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Prochide.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "fad956a6a38abac8a8a0f14cc50f473ec6fc1c9fd204e235b89523183931090b"
		logic_hash = "413f19744240eae0a87d56da1e524e2afa0fe0ec385bd9369218713b13a93495"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e3aa99d48a8554dfaf9f7d947170e6e169b99bf5b6347d4832181e80cc2845cf"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { FF FF 83 BD 9C FC FF FF FF 75 14 BF 7F 22 40 00 }

	condition:
		all of them
}