rule ELASTIC_Linux_Cryptominer_Stak_Bb3153Ac : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Stak (Linux.Cryptominer.Stak)"
		author = "Elastic Security"
		id = "bb3153ac-b11b-4e84-afab-05dab61424ae"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Stak.yar#L80-L98"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5b974b6e6a239bcdc067c53cc8a6180c900052d7874075244dc49aaaa9414cca"
		logic_hash = "e8516a24358b12863fe52c823ca67f0004457017334fe77dabf5f08d6bf2d907"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "c4c33125a1fad9ff393138b333a8cebfd67217e90780c45f73f660ed1fd02753"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 6C 77 61 79 73 22 2C 20 22 6E 6F 5F 6D 6C 63 6B 22 2C 20 22 }

	condition:
		all of them
}