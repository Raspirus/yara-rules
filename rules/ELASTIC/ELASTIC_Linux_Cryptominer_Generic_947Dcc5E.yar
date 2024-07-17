rule ELASTIC_Linux_Cryptominer_Generic_947Dcc5E : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "947dcc5e-be4c-4d31-936f-63d466db2934"
		date = "2024-04-19"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L881-L899"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "7c5a6ac425abe60e8ea5df5dfa8211a7c34a307048b4e677336b735237dcd8fd"
		logic_hash = "c4aac006561386fbfe0fa0fe3df6b6798d2915a3dbfb5384583ebf9b2f413115"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f6087a90a9064b505b60a1c53af008b025064f4a823501cae5f00bbe5157d67b"
		severity = 100
		arch_context = "x86, arm64"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 28 00 00 0A 30 51 9F E5 04 20 94 E5 04 30 A0 E1 38 00 44 E2 00 40 94 E5 00 40 82 E5 04 20 93 E5 04 20 84 E5 0C 20 13 E5 00 30 83 E5 04 00 12 E3 04 30 83 E5 06 00 00 0A 04 10 C2 E3 08 00 12 E3 }

	condition:
		all of them
}