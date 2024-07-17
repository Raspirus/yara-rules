
rule ELASTIC_Linux_Trojan_Kaiji_535F07Ac : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Kaiji (Linux.Trojan.Kaiji)"
		author = "Elastic Security"
		id = "535f07ac-d727-4866-aaed-74d297a1092c"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Kaiji.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "28b2993d7c8c1d8dfce9cd2206b4a3971d0705fd797b9fde05211686297f6bb0"
		logic_hash = "539977c1076b71873135cfe02153da87c0e9ac17122f04570977a22c92d2694f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8853b2a1d5852e436cab2e3402a5ca13839b3cae6fbb56a74b047234b8c1233b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 44 24 10 48 8B 4C 24 08 48 83 7C 24 18 00 74 26 C6 44 24 57 00 48 8B 84 24 98 00 }

	condition:
		all of them
}