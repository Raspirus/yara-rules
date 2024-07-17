rule ELASTIC_Windows_Trojan_Bandook_38497690 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Bandook (Windows.Trojan.Bandook)"
		author = "Elastic Security"
		id = "38497690-6663-47c9-a864-0bbe6a3f7a8b"
		date = "2022-08-10"
		modified = "2022-09-29"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Bandook.yar#L1-L24"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4d079586a51168aac708a9ab7d11a5a49dfe7a16d9ced852fbbc5884020c0c97"
		logic_hash = "199614993f63636764808313f25199348afdf4d537c8dca06f673559e34636b8"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b6debea805a8952b9b7473ad7347645e4aced3ecde8d6e53fa2d82c35b285b3c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "%s~!%s~!%s~!%s~!%s~!%s~!"
		$str2 = "ammyy.abc"
		$str3 = "StealUSB"
		$str4 = "DisableMouseCapture"
		$str5 = "%sSkype\\%s\\config.xml"
		$str6 = "AVE_MARIA"

	condition:
		3 of them
}