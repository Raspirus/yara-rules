rule ELASTIC_Linux_Shellcode_Generic_D2C96B1D : FILE MEMORY
{
	meta:
		description = "Detects Linux Shellcode Generic (Linux.Shellcode.Generic)"
		author = "Elastic Security"
		id = "d2c96b1d-f424-476c-9463-dd34a1da524e"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Shellcode_Generic.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "403d53a65bd77856f7c565307af5003b07413f2aba50869655cdd88ce15b0c82"
		logic_hash = "33d964e22c8e3046f114e8264d18e8b4a0e7b55eca59151b084db7eea07aa0b1"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ee042895d863310ff493fdd33721571edd322e764a735381d236b2c0a7077cfa"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 89 E1 8D 54 24 04 5B B0 0B CD 80 31 C0 B0 01 31 }

	condition:
		all of them
}