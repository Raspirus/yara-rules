rule ELASTIC_Windows_Trojan_Generic_02A87A20 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Generic (Windows.Trojan.Generic)"
		author = "Elastic Security"
		id = "02a87a20-a5b4-44c6-addc-c70b327d7b2c"
		date = "2022-03-04"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Generic.yar#L134-L152"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "13037b749aa4b1eda538fda26d6ac41c8f7b1d02d83f47b0d187dd645154e033"
		logic_hash = "610db1b429ed2ecfc552f73ed4782cb56254e6fc98b728ffeff6938fbcce9616"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "fb25a522888efa729ee6d43a3eec7ade3d08dba394f3592d1c3382a5f7a813c8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 24 3C 8B C2 2B C1 83 F8 01 72 3A 8D 41 01 83 FA 08 89 44 24 38 8D 44 }

	condition:
		all of them
}