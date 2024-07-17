
rule ELASTIC_Windows_Trojan_Cybergate_9996D800 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Cybergate (Windows.Trojan.CyberGate)"
		author = "Elastic Security"
		id = "9996d800-a833-4535-972b-3ee320215bb6"
		date = "2022-02-28"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_CyberGate.yar#L25-L43"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "07b8f25e7b536f5b6f686c12d04edc37e11347c8acd5c53f98a174723078c365"
		logic_hash = "efefc171b6390c9792145973708358f62b18b8d0180feacaf5b9267563c3f7cc"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "eb39d2ff211230aedcf1b5ec0d1dfea108473cc7cba68f5dc1a88479734c02b0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 24 08 8B 44 24 08 83 C4 14 5D 5F 5E 5B C3 55 8B EC 83 C4 F0 }

	condition:
		all of them
}