
rule ELASTIC_Linux_Cryptominer_Camelot_8799D8D6 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Camelot (Linux.Cryptominer.Camelot)"
		author = "Elastic Security"
		id = "8799d8d6-714b-4837-be60-884d78e3b8f3"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Camelot.yar#L198-L216"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4a6d98eae8951e5b9e0a226f1197732d6d14ed45c1b1534d3cdb4413261eb352"
		logic_hash = "4bcd7931aeed09069d5dd248a66f119a2bdf628e03b9abed9ee2de59a149c2bc"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "05c8d7c1d11352f2ec0b5d96a7b2378391ad9f8ae285a1299111aca38352f707"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 72 56 66 48 32 37 48 4D 5A 75 6D 74 46 75 4A 72 6D 48 47 38 }

	condition:
		all of them
}