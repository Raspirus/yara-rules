rule ELASTIC_Linux_Cryptominer_Generic_76Cb94A9 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "76cb94a9-5a3f-483c-91f3-aa0e3c27f7ba"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L381-L399"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1320d7a2b5e3b65fe974a95374b4ea7ed1a5aa27d76cd3d9517d3a271121103f"
		logic_hash = "758ee41048c94576e7a872bfdacc6b6f2be3d460169905c876585037e11fdaa8"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "623a33cc95af46b8f0d557c69f8bf72db7c57fe2018b7a911733be4ddd71f073"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 8C 24 98 00 00 00 31 C9 80 7A 4A 00 48 89 74 24 18 48 89 54 }

	condition:
		all of them
}