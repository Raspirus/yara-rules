
rule ELASTIC_Linux_Trojan_Patpooty_F90C7E43 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Patpooty (Linux.Trojan.Patpooty)"
		author = "Elastic Security"
		id = "f90c7e43-0c32-487f-a7c2-8290b341019c"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Patpooty.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "79475a66be8741d9884bc60f593c81a44bdb212592cd1a7b6130166a724cb3d3"
		logic_hash = "2d995722b06ce51a5378e395896764421f84afcf6b13855a87ed43d9b9e38982"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b0b0fd8da224bcd1c048c5578ed487d119f9bff4fb465f77d3043cf77d904f3d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { C2 48 39 C2 75 F1 C7 43 58 01 00 00 00 C7 43 54 01 00 00 00 C7 43 50 01 00 }

	condition:
		all of them
}