
rule ELASTIC_Windows_Generic_Threat_A440F624 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "a440f624-c7ec-4f26-bfb5-982bae5f6887"
		date = "2024-01-07"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L649-L668"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "3564fec3d47dfafc7e9c662654865aed74aedeac7371af8a77e573ea92cbd072"
		logic_hash = "23c759a0db5698b28a69232077a6b714f71e8eaa069d2f02a7d3efc48b178a2b"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "0f538f8f4eb2e71fb74d8305a179fc2ad880ab5a4cfd37bd35b5da2629ed892c"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 2E 20 49 50 20 3D 20 25 73 2C 20 50 6F 72 74 20 3D 20 25 64 2C 20 73 6B 20 3D 20 25 64 }
		$a2 = { 2E 20 49 50 20 3D 20 25 73 2C 20 50 6F 72 74 20 3D 20 25 64 2C 20 4C 65 6E 20 3D 20 25 64 }

	condition:
		all of them
}