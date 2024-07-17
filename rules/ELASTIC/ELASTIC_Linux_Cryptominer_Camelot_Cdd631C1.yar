rule ELASTIC_Linux_Cryptominer_Camelot_Cdd631C1 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Camelot (Linux.Cryptominer.Camelot)"
		author = "Elastic Security"
		id = "cdd631c1-2c03-47dd-b50a-e8c0b9f67271"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Camelot.yar#L258-L276"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "91549c171ae7f43c1a85a303be30169932a071b5c2b6cf3f4913f20073c97897"
		logic_hash = "5e4b26a74fc3737c068917c7c1228048f885ac30fc326a2844611f7e707d1300"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "fa174ac25467ab6e0f11cf1f0a5c6bf653737e9bbdc9411aabeae460a33faa5e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 00 5F 5A 4E 35 78 6D 72 69 67 35 50 6F 6F 6C 73 }

	condition:
		all of them
}