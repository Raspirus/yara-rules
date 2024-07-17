
rule ELASTIC_Linux_Trojan_Cerbu_69D5657E : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Cerbu (Linux.Trojan.Cerbu)"
		author = "Elastic Security"
		id = "69d5657e-1fe9-4367-b478-218c278c7fbc"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Cerbu.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f10bf3cf2fdfbd365d3c2d8dedb2d01b85236eaa97d15370dbcb5166149d70e9"
		logic_hash = "644e8d5a1b5c8618e71497f21b0244215924e293e274b9164692dd927cd74ba8"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7dfaebc6934c8fa97509831e0011f2befd0dbc24a68e4a07bc1ee0decae45a42"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { E8 5B 5E C9 C3 55 89 E5 83 EC 08 83 C4 FC FF 75 0C 6A 05 FF }

	condition:
		all of them
}