
rule ELASTIC_Windows_Generic_Threat_B1Ef4828 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "b1ef4828-10bd-41f8-84b5-041bf3147c0b"
		date = "2024-03-04"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2860-L2879"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "29b20ff8ebad05e4a33c925251d08824ca155f5d9fa72d6f9e359e6ec6c61279"
		logic_hash = "d5d63f38308c6f8e5ca54567c7c8b93fcde69601fbcc28d56d5231edd28163cf"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "e867d9a0a489d95898f85578c71d7411eac3142539fcc88df51d1cf048d351a9"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 70 36 72 20 74 24 76 28 78 2C 7A 30 7C 34 7E 38 7E 3C 7E 40 7E 54 7E 74 7E 7C 5D }
		$a2 = { 7E 30 7E 34 7E 43 7E 4F 7E 5A 7E 6E 7E 79 7E }

	condition:
		all of them
}