rule ELASTIC_Linux_Shellcode_Generic_8Ac37612 : FILE MEMORY
{
	meta:
		description = "Detects Linux Shellcode Generic (Linux.Shellcode.Generic)"
		author = "Elastic Security"
		id = "8ac37612-aec8-4376-8269-2594152ced8a"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Shellcode_Generic.yar#L121-L139"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c199b902fa4b0fcf54dc6bf3e25ad16c12f862b47e055863a5e9e1f98c6bd6ca"
		logic_hash = "c0af751bc54dcd9cf834fa5fe9fa120be5e49a56135ebb72fd6073948e956929"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "97a3d3e7ff4c9ae31f71e609d10b3b848cb0390ae2d1d738ef53fd23ff0621bc"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 89 E3 ?? 53 89 E1 B0 0B CD 80 00 47 43 43 3A }

	condition:
		all of them
}