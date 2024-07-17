
rule ELASTIC_Windows_Generic_Threat_C8424507 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "c8424507-34e1-4649-a4e4-3e0a0f62dfb0"
		date = "2024-05-22"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L3424-L3443"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d556b02733385b823cfe4db7e562e90aa520e2e6fb00fceb76cc0a6a1ff47692"
		logic_hash = "78d56257cb6e1d67f9343ee30b844fe20138e27ca3b6312a07112e5dbb797851"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "8dfb14903b32c118492ae7e0aab9cf634c58ea93fcbc7759615209f61b3b3d6b"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 78 75 73 65 68 6F 62 69 6D 6F 7A 61 63 6F 67 6F 6A 69 68 6F 67 69 76 6F }
		$a2 = { 62 65 6D 69 74 69 76 65 67 69 77 6F 6D 65 7A 75 76 65 62 61 67 }

	condition:
		all of them
}