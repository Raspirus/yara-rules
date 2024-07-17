
rule ELASTIC_Linux_Trojan_Ladvix_C9888Edb : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Ladvix (Linux.Trojan.Ladvix)"
		author = "Elastic Security"
		id = "c9888edb-0f82-4c7a-b501-4e4d3c9c64e3"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Ladvix.yar#L40-L58"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1d798e9f15645de89d73e2c9d142189d2eaf81f94ecf247876b0b865be081dca"
		logic_hash = "608f2340b0ee4b843933d8137aa0908583a6de477e6c472fb4bd2e5bb62dfb80"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e0e0d75a6de7a11b2391f4a8610a6d7c385df64d43fa1741d7fe14b279e1a29a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { E8 01 83 45 E4 01 8B 45 E4 83 F8 57 76 B5 83 45 EC 01 8B 45 EC 48 }

	condition:
		all of them
}