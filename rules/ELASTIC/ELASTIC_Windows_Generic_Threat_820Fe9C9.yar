rule ELASTIC_Windows_Generic_Threat_820Fe9C9 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "820fe9c9-2abc-4dd5-84e2-a74fbded4dc6"
		date = "2024-01-11"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L934-L952"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1102a499b8a863bdbfd978a1d17270990e6b7fe60ce54b9dd17492234aad2f8c"
		logic_hash = "81a1359bd5781e1eefb6ae06c6b2ad9e94cc6318c1f81f84c06f0b236b6e84d1"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "e43f4fee9e23233bf8597decac79bda4790b5682f5e0fe86e3a13cb18724ea3e"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 2E 2A 73 74 72 75 63 74 20 7B 20 46 20 75 69 6E 74 70 74 72 3B 20 58 30 20 63 68 61 6E 20 73 74 72 69 6E 67 3B 20 58 31 20 62 6F 6F 6C 20 7D }

	condition:
		all of them
}