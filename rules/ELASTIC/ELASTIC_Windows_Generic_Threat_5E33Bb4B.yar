rule ELASTIC_Windows_Generic_Threat_5E33Bb4B : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "5e33bb4b-830e-4814-b6cf-d5e5b4da7ada"
		date = "2024-03-04"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L3043-L3061"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "13c06d7b030a46c6bb6351f40184af9fafaf4c67b6a2627a45925dd17501d659"
		logic_hash = "7e2002c3917ccab7d9f56a7aa20ea75be71aa7fdc64b7c3f87edb68be38e74b2"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "a08b9db015f1b6f62252d456b1b0cd0fdec1e19cdd2bc1400fe2bf76150ea07b"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 43 3A 5C 55 73 65 72 73 5C 61 64 6D 69 6E 5C 44 65 73 6B 74 6F 70 5C 57 6F 72 6B 5C 46 69 6C 65 49 6E 73 74 61 6C 6C 65 72 5C 52 65 6C 65 61 73 65 5C 46 69 6C 65 49 6E 73 74 61 6C 6C 65 72 2E 70 64 62 }

	condition:
		all of them
}