
rule ELASTIC_Linux_Trojan_Gafgyt_Dd0D6173 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "dd0d6173-b863-45cf-9348-3375a4e624cf"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L872-L890"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c5a317d0d8470814ff343ce78ad2428ebb3f036763fcf703a589b6c4d33a3ec6"
		logic_hash = "7061edef1981e2b93bcdd8be47c0f6067acc140a543eed748bf0513f182e0a59"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "5e2cb111c2b712951b71166111d339724b4f52b93f90cb474f1e67598212605f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 55 F8 8B 45 F0 89 42 0C 48 8B 55 F8 8B 45 F4 89 42 10 C9 C3 55 48 }

	condition:
		all of them
}