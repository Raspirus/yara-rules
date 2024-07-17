rule ELASTIC_Linux_Trojan_Xorddos_56Bd04D3 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Xorddos (Linux.Trojan.Xorddos)"
		author = "Elastic Security"
		id = "56bd04d3-6b52-43f4-b170-637feb86397a"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Xorddos.yar#L297-L315"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0d2ce3891851808fb36779a348a83bf4aa9de1a2b2684fd0692434682afac5ec"
		logic_hash = "47a33fcd69dd78cbc6c3274aeaa8dddabe119ae65b59077e1807657b8a67fed3"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "25cd85e8e65362a993a314f2fc500266fce2f343d21a2e91b146dafbbe8186db"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 5C 87 5C 24 04 89 5C 24 04 8B 1C 24 8D 64 24 04 8B 00 8B F6 87 }

	condition:
		all of them
}