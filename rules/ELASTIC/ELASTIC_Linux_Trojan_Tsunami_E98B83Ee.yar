
rule ELASTIC_Linux_Trojan_Tsunami_E98B83Ee : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Tsunami (Linux.Trojan.Tsunami)"
		author = "Elastic Security"
		id = "e98b83ee-0533-481a-9947-538bd2f99b6b"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Tsunami.yar#L181-L199"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "cf1ca1d824c8687e87a5b0275a0e39fa101442b4bbf470859ddda9982f9b3417"
		logic_hash = "8b16c0fee991ee2143a20998097066a90b1f20060bac7b42e5c3188adcdc7907"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b5440c783bc18e23f27a3131ccce4629f8d0ceea031971cbcdb69370ab52e935"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 45 FE 00 00 EB 16 48 8B 55 D8 0F B7 02 0F B7 C0 01 45 E0 48 83 45 }

	condition:
		all of them
}