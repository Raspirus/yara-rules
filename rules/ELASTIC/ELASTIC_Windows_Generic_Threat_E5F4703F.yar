rule ELASTIC_Windows_Generic_Threat_E5F4703F : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "e5f4703f-e834-4904-9036-a8c5996058c8"
		date = "2024-01-09"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L793-L811"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "362bda1fad3fefce7d173617909d3c1a0a8e234e22caf3215ee7c6cef6b2743b"
		logic_hash = "f81476d5e5a9bcb42b32d6ec3d4b620165f2878c50691ecf59ef6f34b6ad9d1b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3072ea028b0716e88820782a2658d1f424d57bd988ccfcc1581991649cf52b19"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 83 E4 F8 83 EC 08 83 79 14 08 56 57 8B F1 72 02 8B 31 8B 41 10 8B CE 8D 3C 46 8B D7 E8 AC FA FF FF 8B 75 08 2B F8 D1 FF 0F 57 C0 57 50 0F 11 06 8B CE C7 46 10 00 00 00 00 C7 46 14 00 }

	condition:
		all of them
}