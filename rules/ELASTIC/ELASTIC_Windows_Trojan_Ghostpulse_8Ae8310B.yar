rule ELASTIC_Windows_Trojan_Ghostpulse_8Ae8310B : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Ghostpulse (Windows.Trojan.GhostPulse)"
		author = "Elastic Security"
		id = "8ae8310b-4ead-4b5c-be73-7db365470891"
		date = "2024-05-27"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_GhostPulse.yar#L65-L84"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5b64f91b41a7390d89cd3b1fccf02b08b18b7fed17a43b0bfac63d75dc0df083"
		logic_hash = "b3873a3c728e98d65984033620c0ac8ee93be21db5b6d9bd4665b9f7d0d759fa"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "61213fd4ce9ddebdc7de8e6b23827347af3cbddd61254f95917e9af6b8a2b7b2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 48 8B 84 24 ?? 0D 00 00 8B 40 14 0F BA E8 09 48 8B 8C 24 ?? 0D 00 00 89 41 14 48 8B 84 24 ?? 0D 00 00 48 8B 8C 24 ?? 05 00 00 48 89 88 C0 ?? 00 00 }
		$b = { BA C8 90 F0 B2 48 8B ?? ?? ?? E8 ?? ?? ?? 00 48 89 ?? ?? ?? 07 00 00 BA 9C 6C DA DC 48 8B ?? ?? ?? E8 ?? ?? ?? 00 48 89 ?? ?? ?? 07 00 00 BA 8D 20 4A A1 48 8B ?? ?? ?? E8 ?? ?? ?? 00 48 89 ?? ?? ?? 07 00 00 BA D4 7C 1A A8 }

	condition:
		any of them
}