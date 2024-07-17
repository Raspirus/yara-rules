rule ELASTIC_Linux_Hacktool_Bruteforce_Eb83B6Aa : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Bruteforce (Linux.Hacktool.Bruteforce)"
		author = "Elastic Security"
		id = "eb83b6aa-d7b5-4d10-9258-4bf619fc6582"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Bruteforce.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "8dec88576f61f37fbaece3c30e71d338c340c8fb9c231f9d7b1c32510d2c3167"
		logic_hash = "bc79860e414d07ee8000eea3d61827272d66faa90a8bf6c65fcda90a4bd762ef"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7767bf57c57d398f27646f5ae2bcda07d6c62959becb31a5186ff0b027ff02b4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 10 89 45 EC EB 04 83 6D EC 01 83 7D EC 00 74 12 8B 45 EC 8D }

	condition:
		all of them
}