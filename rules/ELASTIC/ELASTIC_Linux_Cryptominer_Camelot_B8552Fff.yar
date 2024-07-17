
rule ELASTIC_Linux_Cryptominer_Camelot_B8552Fff : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Camelot (Linux.Cryptominer.Camelot)"
		author = "Elastic Security"
		id = "b8552fff-29a9-4e09-810a-b4b52a7a3fb4"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Camelot.yar#L158-L176"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "cdd3d567fbcbdd6799afad241ae29acbe4ab549445e5c4fc0678d16e75b40dfa"
		logic_hash = "476b800422b6d98405d8bde727bb589c5cae36723436b269beaa65381b3d0abe"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "d5998e0bf7df96dd21d404658589fb37b405398bd3585275419169b30c72ce62"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 18 8B 44 24 1C 8B 50 0C 83 E8 04 8B 0A FF 74 24 28 FF 74 24 28 FF 74 }

	condition:
		all of them
}