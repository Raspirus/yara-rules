
rule ELASTIC_Macos_Trojan_Metasploit_5E5B685F : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Metasploit (MacOS.Trojan.Metasploit)"
		author = "Elastic Security"
		id = "5e5b685f-1b6b-4102-b54d-91318e418c6c"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Metasploit.yar#L255-L273"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "cdf0a3c07ef1479b53d49b8f22a9f93adcedeea3b869ef954cc043e54f65c3d0"
		logic_hash = "003fb4f079b125f37899a2b3cb62d80edd5b3e5ccbed5bc1ea514a4a173d329d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "52c41d4fc4d195e702523dd2b65e4078dd967f9c4e4b1c081bc04d88c9e4804f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a1 = { 00 00 F4 90 90 90 90 55 48 89 E5 48 81 EC 60 20 00 00 89 F8 48 8B 0D 74 23 00 }

	condition:
		all of them
}