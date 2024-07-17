rule ELASTIC_Linux_Webshell_Generic_41A5Fa40 : FILE MEMORY
{
	meta:
		description = "Detects Linux Webshell Generic (Linux.Webshell.Generic)"
		author = "Elastic Security"
		id = "41a5fa40-a4e7-4c97-a3b9-3700743265df"
		date = "2021-06-28"
		modified = "2021-09-16"
		reference = "18ac7fbc3d8d3bb8581139a20a7fee8ea5b7fcfea4a9373e3d22c71bae3c9de0"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Webshell_Generic.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "574148bc58626aac00add1989c65ad56315c7e2a8d27c7b96be404d831a7a576"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "49e0d55579453ec37c6757ddb16143d8e86ad7c7c4634487a1bd2215cd22df83"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 5A 46 55 6C 73 6E 55 6B 56 52 56 55 56 54 56 46 39 56 55 6B 6B }

	condition:
		all of them
}