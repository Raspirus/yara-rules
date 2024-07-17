
rule ELASTIC_Windows_Ransomware_Hive_B97Ec33B : FILE MEMORY
{
	meta:
		description = "Detects Windows Ransomware Hive (Windows.Ransomware.Hive)"
		author = "Elastic Security"
		id = "b97ec33b-d4cf-4b70-8ce8-8a5d20448643"
		date = "2021-08-26"
		modified = "2022-01-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Hive.yar#L47-L65"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "50ad0e6e9dc72d10579c20bb436f09eeaa7bfdbcb5747a2590af667823e85609"
		logic_hash = "10034d9f53fd5099a423269e0c42c01eac18318f5d11599e1390912c8fd7af25"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7f2c2d299942390d953599b180ed191d9db999275545a7ba29059fd49b858087"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 74 C3 8B 44 24 78 8B 08 8B 50 04 8B 40 08 89 0C 24 89 54 24 04 89 44 }

	condition:
		all of them
}