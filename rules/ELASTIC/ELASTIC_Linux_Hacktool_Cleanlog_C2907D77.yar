
rule ELASTIC_Linux_Hacktool_Cleanlog_C2907D77 : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Cleanlog (Linux.Hacktool.Cleanlog)"
		author = "Elastic Security"
		id = "c2907d77-6ea9-493f-a7b3-4a0795da0a1d"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Cleanlog.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "613ac236130ab1654f051d6f0661fa62414f3bef036ea4cc585b4b21a4bb9d2b"
		logic_hash = "39b72973bbcddf14604b8ea08339657cba317c23fd4d69d4aa0903b262397988"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "131c71086c30ab22ca16b3020470561fa3d32c7ece9a8faa399a733e8894da30"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 89 E5 48 83 EC 10 89 7D FC 83 7D FC 00 7E 11 8B 45 FC BE 09 00 }

	condition:
		all of them
}