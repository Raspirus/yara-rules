
rule ELASTIC_Linux_Trojan_Psybnc_Ab3396D5 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Psybnc (Linux.Trojan.Psybnc)"
		author = "Elastic Security"
		id = "ab3396d5-388b-4730-9a55-581c327a2769"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Psybnc.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c5ec84e7cc891af25d6319abb07b1cedd90b04cbb6c8656c60bcb07e60f0b620"
		logic_hash = "8c083f66fc252a88395bb954a67d710d64f5b68efb9df4b60b260302874b400a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1180e02d3516466457f48dc614611a6949a4bf21f6a294f6384892db30dc4171"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 53 54 00 55 53 45 52 4F 4E 00 30 00 50 25 64 00 58 30 31 00 }

	condition:
		all of them
}