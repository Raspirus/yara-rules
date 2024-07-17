rule ELASTIC_Linux_Generic_Threat_900Ffdd4 : FILE MEMORY
{
	meta:
		description = "Detects Linux Generic Threat (Linux.Generic.Threat)"
		author = "Elastic Security"
		id = "900ffdd4-085e-4d6b-af7b-2972157dcefd"
		date = "2024-02-21"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Generic_Threat.yar#L656-L674"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a3e1a1f22f6d32931d3f72c35a5ee50092b5492b3874e9e6309d015d82bddc5d"
		logic_hash = "eb69bfc146b32e790fffdf4588b583335d2006182070b53fec43bb6e4971d779"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f03d39e53b06dd896bfaff7c94beaa113df1831dc397ef0ea8bea63156316a1b"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { 20 48 89 7D E8 89 75 E4 48 83 7D E8 00 74 5C C7 45 FC 00 00 00 00 EB 3D 8B 45 FC 48 98 48 C1 E0 04 48 89 C2 48 8B 45 E8 48 01 D0 48 8B 00 48 85 C0 74 1E 8B 45 FC 48 98 48 C1 E0 04 48 }

	condition:
		all of them
}