
rule ELASTIC_Windows_Generic_Threat_79174B5C : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "79174b5c-bc1d-40b2-b2e9-f3ddd3ba226c"
		date = "2023-12-18"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L262-L280"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c15118230059e85e7a6b65fe1c0ceee8997a3d4e9f1966c8340017a41e0c254c"
		logic_hash = "06a2f0613719f1273a6b3f62f248c22b1cab2fe6054904619e3720f3f6c55e2e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1e709e5cb8302ea19f9ee93e88f7f910f4271cf1ea2a6c92946fa26f68c63f4d"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 83 EC 48 56 57 6A 0F 33 C0 59 8D 7D B9 F3 AB 8B 75 0C 6A 38 66 AB 8B 4E 14 AA 8B 46 10 89 4D FC 89 45 F8 59 C1 E8 03 83 E0 3F C6 45 B8 80 3B C1 72 03 6A 78 59 2B C8 8D 45 B8 51 50 56 }

	condition:
		all of them
}