
rule ELASTIC_Linux_Cryptominer_Xmrminer_67Bf4B54 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Xmrminer (Linux.Cryptominer.Xmrminer)"
		author = "Elastic Security"
		id = "67bf4b54-aa02-4f4c-ba70-3f2db1418c7e"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Xmrminer.yar#L61-L79"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "9d33fba4fda6831d22afc72bf3d6d5349c5393abb3823dfa2a5c9e391d2b9ddf"
		logic_hash = "448f5b9dc3c17984464c15f6d542f495a52b0531acc362dedfe3d1a20b932969"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "5f2fae0eee79dac3c202796d987ad139520fadae145c84ab5769d46afb2518c2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 46 70 4A 8B 2C E0 83 7D 00 03 74 DA 8B 4D 68 85 C9 74 DC 45 }

	condition:
		all of them
}