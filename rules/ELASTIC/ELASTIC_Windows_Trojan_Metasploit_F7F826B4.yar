
rule ELASTIC_Windows_Trojan_Metasploit_F7F826B4 : FILE MEMORY
{
	meta:
		description = "Identifies metasploit kernel->user shellcode. Likely used in ETERNALBLUE and BlueKeep exploits."
		author = "Elastic Security"
		id = "f7f826b4-6456-4819-bc0c-993aeeb7e325"
		date = "2021-03-23"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Metasploit.yar#L61-L79"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "2f5264e07c65d5ef4efe49a48c24ccef9a4b9379db581d2cf18e1131982e6f2f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "9b07dc54d5015d0f0d84064c5a989f94238609c8167cae7caca8665930a20f81"
		threat_name = "Windows.Trojan.Metasploit"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 48 92 31 C9 51 51 49 89 C9 4C 8D 05 0? 00 00 00 89 CA 48 83 EC 20 FF D0 48 83 C4 30 C3 }

	condition:
		$a1
}