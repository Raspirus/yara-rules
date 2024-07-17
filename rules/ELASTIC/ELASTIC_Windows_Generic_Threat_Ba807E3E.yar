rule ELASTIC_Windows_Generic_Threat_Ba807E3E : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "ba807e3e-13d8-49e0-ad99-32994d490e8b"
		date = "2024-02-14"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2558-L2576"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "cabd0633b37e6465ece334195ff4cc5c3f44cfe46211165efc07f4073aed1049"
		logic_hash = "896eedb949eec6dff3e867ae3179b741382dd25ba06c6db452ac1ae5bc6bc757"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "e6ea7577f8f21e778d21b4651bf55e66ec53fb6d80d68f2ab344261be50d03cc"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 7D 4A 36 35 2B 7E 2E 2C 2F 37 2C 3D 31 7E 3B 3D 30 30 2F 2A 7E 3C 39 7E 2C 29 30 7E 35 30 7E 5A 4F 4B 7E 31 2F 3A 39 70 }

	condition:
		all of them
}