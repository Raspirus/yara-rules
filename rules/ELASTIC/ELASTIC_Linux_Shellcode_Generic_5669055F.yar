rule ELASTIC_Linux_Shellcode_Generic_5669055F : FILE MEMORY
{
	meta:
		description = "Detects Linux Shellcode Generic (Linux.Shellcode.Generic)"
		author = "Elastic Security"
		id = "5669055f-8ce7-4163-af06-cb265fde3eef"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Shellcode_Generic.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "87ef4def16d956cdfecaea899cbb55ff59a6739bbb438bf44a8b5fec7fcfd85b"
		logic_hash = "735b8dc7fff3c9cc96646a4eb7c5afd70be19dcc821e9e26ce906681130746be"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "616fe440ff330a1d22cacbdc2592c99328ea028700447724d2d5b930554a22f4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 00 31 C0 31 DB 31 C9 B0 17 CD 80 31 C0 51 B1 06 }

	condition:
		all of them
}