
rule ELASTIC_Windows_Trojan_Darkvnc_Bd803C2E : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Darkvnc (Windows.Trojan.DarkVNC)"
		author = "Elastic Security"
		id = "bd803c2e-77bd-4b8c-bdfa-11a9bd54a454"
		date = "2023-01-23"
		modified = "2023-02-01"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_DarkVNC.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0fcc1b02fdaf211c772bd4fa1abcdeb5338d95911c226a9250200ff7f8e45601"
		logic_hash = "d9e8a42a424d6a186939682e1cd2ed794c8a3765824188e863b1b2829650e2d5"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "131f4b3ef5b01720a52958058ecc4c3681ed0ca975a1a06cd034d7205680e710"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "BOT-%s(%s)_%S-%S%u%u" wide fullword
		$a2 = "{%08X-%04X-%04X-%04X-%08X%04X}" wide fullword
		$a3 = "monitor_off / monitor_on" ascii fullword
		$a4 = "bot_shell >" ascii fullword
		$a5 = "keyboard and mouse are blocked !" ascii fullword

	condition:
		all of them
}