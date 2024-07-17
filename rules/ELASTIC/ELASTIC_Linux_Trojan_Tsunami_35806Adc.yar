rule ELASTIC_Linux_Trojan_Tsunami_35806Adc : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Tsunami (Linux.Trojan.Tsunami)"
		author = "Elastic Security"
		id = "35806adc-9bac-4481-80c8-a673730d5179"
		date = "2021-12-13"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Tsunami.yar#L460-L478"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "15e7942ebf88a51346d3a5975bb1c2d87996799e6255db9e92aed798d279b36b"
		logic_hash = "6e9d3e5c0a33208d1b5f4f84f8634955e70bd63395b367cd1ece67798ce5e502"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f0b4686087ddda1070b62ade7ad7eb69d712e15f5645aaba24c0f5b124a283ac"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 85 3C 93 48 1F 03 36 84 C0 4B 28 7F 18 86 13 08 10 1F EC B0 73 }

	condition:
		all of them
}