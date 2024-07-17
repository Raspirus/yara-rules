rule ELASTIC_Linux_Cryptominer_Generic_E73F501E : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "e73f501e-019c-4281-ae93-acde7ad421af"
		date = "2021-12-13"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L761-L779"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2f646ced4d05ba1807f8e08a46ae92ae3eea7199e4a58daf27f9bd0f63108266"
		logic_hash = "2f6187f3447f9409485e9e8aa047114aa3c38bcc338106c3ed8680152dff121a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "bd9e6f2548c918b2c439a047410b6b239c3993a3dbd85bfd70980c64d11a6c5c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 03 51 8A 92 FF F3 20 01 DE 63 AF 8B 54 73 0A 65 83 64 88 60 }

	condition:
		all of them
}