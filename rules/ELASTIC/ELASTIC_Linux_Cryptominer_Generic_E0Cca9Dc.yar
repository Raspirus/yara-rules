
rule ELASTIC_Linux_Cryptominer_Generic_E0Cca9Dc : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "e0cca9dc-0f3e-42d8-bb43-0625f4f9bfe1"
		date = "2022-01-05"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L841-L859"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "59a1d8aa677739f2edbb8bd34f566b31f19d729b0a115fef2eac8ab1d1acc383"
		logic_hash = "fa4089f74fc78e99427b4e8eda9f8348e042dc876c7281a4a2173c83076bfbd2"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e7bc17ba356774ed10e65c95a8db3b09d3b9be72703e6daa9b601ea820481db7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 54 24 40 48 8D 94 24 C0 00 00 00 F3 41 0F 6F 01 48 89 7C 24 50 48 89 74 }

	condition:
		all of them
}