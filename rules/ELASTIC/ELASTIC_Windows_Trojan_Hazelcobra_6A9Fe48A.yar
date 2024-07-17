
rule ELASTIC_Windows_Trojan_Hazelcobra_6A9Fe48A : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Hazelcobra (Windows.Trojan.HazelCobra)"
		author = "Elastic Security"
		id = "6a9fe48a-6fd9-4bce-ac43-254c02d6b3a4"
		date = "2023-11-01"
		modified = "2023-11-01"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_HazelCobra.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b5acf14cdac40be590318dee95425d0746e85b1b7b1cbd14da66f21f2522bf4d"
		logic_hash = "dc4d561497c2e3da270d305ceaf3194b48d64c0d8e212ee6f03a2d89c8e006e8"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4dc883be5fb6aae0dac0ec5d64baf24f0f3aaded6d759ec7dccb1a2ae641ae7b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 83 E9 37 48 63 C2 F6 C2 01 75 0C C0 E1 04 48 D1 F8 88 4C 04 40 EB 07 }
		$s1 = "Data file loaded. Running..." fullword
		$s2 = "No key in args" fullword
		$s3 = "Can't read data file" fullword

	condition:
		$a1 or all of ($s*)
}