rule ELASTIC_Linux_Generic_Threat_1973391F : FILE MEMORY
{
	meta:
		description = "Detects Linux Generic Threat (Linux.Generic.Threat)"
		author = "Elastic Security"
		id = "1973391f-b9a2-465d-8990-51c6e9fab84b"
		date = "2024-02-21"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Generic_Threat.yar#L882-L901"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "7bd76010f18061aeaf612ad96d7c03341519d85f6a1683fc4b2c74ea0508fe1f"
		logic_hash = "632a43b68e498f463ff5dfa78212646b8bd108ea47ff11164c8c1a69e830c1ac"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "90a261afd81993057b084c607e27843ff69649b3d90f4d0b52464e87fdf2654d"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { 70 69 63 6B 75 70 20 2D 6C 20 2D 74 20 66 69 66 6F 20 2D 75 }
		$a2 = { 5B 2D 5D 20 43 6F 6E 6E 65 63 74 20 66 61 69 6C 65 64 2E }

	condition:
		all of them
}