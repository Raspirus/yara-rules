
rule ELASTIC_Linux_Trojan_Godlua_Ed8E6228 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Godlua (Linux.Trojan.Godlua)"
		author = "Elastic Security"
		id = "ed8e6228-d5be-4b8e-8dc2-7072b1236bfa"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Godlua.yar#L1-L18"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "848ef3b198737f080f19c5fa55dfbc31356427398074f9125c65cb532c52ce7a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "9b73c2bbbe1bc43ae692f03b19cd23ad701f0120dff0201dd2a6722c44ea51ed"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { C0 18 48 89 45 E8 EB 60 48 8B 85 58 FF FF FF 48 83 C0 20 48 89 }

	condition:
		all of them
}