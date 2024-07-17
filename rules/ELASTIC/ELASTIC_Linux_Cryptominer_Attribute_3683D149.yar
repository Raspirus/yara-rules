rule ELASTIC_Linux_Cryptominer_Attribute_3683D149 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Attribute (Linux.Cryptominer.Attribute)"
		author = "Elastic Security"
		id = "3683d149-fa9c-4dbb-85b9-8ce2b1d1d128"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Attribute.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ec9e74d52d745275718fe272bfd755335739ad5f680f73f5a4e66df6eb141a63"
		logic_hash = "71aa8aa4171671af4aa0271b64da95ac1d8766de12a949c97ebcac9369224ecd"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "31f45578eab3c94cff52056a723773d41aaad46d529b1a2063a0610d5948a633"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 20 74 6F 20 66 61 73 74 29 20 6F 72 20 39 20 28 61 75 74 6F }

	condition:
		all of them
}