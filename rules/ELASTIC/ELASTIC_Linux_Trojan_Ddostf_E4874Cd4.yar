
rule ELASTIC_Linux_Trojan_Ddostf_E4874Cd4 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Ddostf (Linux.Trojan.Ddostf)"
		author = "Elastic Security"
		id = "e4874cd4-50e3-4a4c-b14c-976e29aaaaae"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Ddostf.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1015b9aef1f749dfc31eb33528c4a4169035b6d73542e068b617965d3e948ef2"
		logic_hash = "1523fe8f7bbbc7e42f8c2efe5b28dd381007846a1ba7078a6f1a30aedace884b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "dfbf7476794611718a1cd2c837560423e3a6c8b454a5d9eecb9c6f9d31d01889"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { E4 01 8B 45 F0 2B 45 F4 89 C2 8B 45 E4 39 C2 73 82 8B 45 EC }

	condition:
		all of them
}