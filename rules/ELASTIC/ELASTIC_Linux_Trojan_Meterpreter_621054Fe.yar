rule ELASTIC_Linux_Trojan_Meterpreter_621054Fe : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Meterpreter (Linux.Trojan.Meterpreter)"
		author = "Elastic Security"
		id = "621054fe-bbdf-445c-a503-ccba82b88243"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Meterpreter.yar#L40-L57"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "18f22bb0aa66ec2ecdaa9ca0e0d00ee59a2c9a3f231bd71915140e4464a4ea78"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "13cb03783b1d5f14cadfaa9b938646d5edb30ea83702991a81cc4ca82e4637dc"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 28 85 D2 75 0A 8B 50 2C 83 C8 FF 85 D2 74 03 8B 42 64 5D C3 55 }

	condition:
		all of them
}