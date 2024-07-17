rule ELASTIC_Windows_Generic_Threat_492D7223 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "492d7223-4e03-4a77-83e5-ed85e052f846"
		date = "2024-03-26"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L3364-L3382"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c0d9c9297836aceb4400bcb0877d1df90ca387f18f735de195852a909c67b7ef"
		logic_hash = "9fb2a00def86ed8476d906514a0bc630e28093ac37d757541d8801d2c8e0efc3"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "71a1bce450522a0a6ff38d2f84ab91e2e9db360736c2f7233124a0b0dc4d0431"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 89 E5 53 57 56 83 EC 24 ?? ?? ?? ?? ?? 31 C9 85 C0 0F 94 C1 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 C8 40 FF E0 }

	condition:
		all of them
}