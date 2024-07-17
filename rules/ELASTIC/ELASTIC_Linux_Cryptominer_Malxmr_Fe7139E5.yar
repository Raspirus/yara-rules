rule ELASTIC_Linux_Cryptominer_Malxmr_Fe7139E5 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Malxmr (Linux.Cryptominer.Malxmr)"
		author = "Elastic Security"
		id = "fe7139e5-3c8e-422c-aaf7-e683369d23d4"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Malxmr.yar#L200-L218"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "8b13dc59db58b6c4cd51abf9c1d6f350fa2cb0dbb44b387d3e171eacc82a04de"
		logic_hash = "d1ef74f2a74950845091b2ebc2f7fd05980bcbd2aea4fdd9549c54cec1768501"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4af38ca3ec66ca86190e6196a9a4ba81a0a2b77f88695957137f6cda8fafdec9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { FF 74 5B 48 29 F9 49 89 DC 4C 8D 69 01 49 D1 ED 4C 01 E9 4D 8D 6C }

	condition:
		all of them
}