rule ELASTIC_Windows_Trojan_Icedid_D8B23Cd6 : FILE MEMORY
{
	meta:
		description = "IcedID VNC server"
		author = "Elastic Security"
		id = "d8b23cd6-c20c-40c9-a8e9-80d68e709764"
		date = "2023-01-03"
		modified = "2023-01-03"
		reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_IcedID.yar#L263-L294"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "bd4da2f84c29437bc7efe9599a3a41f574105d449ac0d9b270faaca8795153ab"
		logic_hash = "47e427a4f088de523115f438cad9fc26233158b0518d87703c282df351110762"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "d47af2b50d0fb07858538fdb9f53fee008b49c9b1d015e4593199407673e0e21"
		threat_name = "Windows.Trojan.IcedID"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "User idle %u sec / Locked: %s / ScreenSaver: %s" wide
		$a2 = "No VNC HOOK" wide
		$a3 = "Webcam %u" wide
		$a4 = "rundll32.exe shell32.dll,#61"
		$a5 = "LAP WND"
		$a6 = "FG WND"
		$a7 = "CAP WND"
		$a8 = "HDESK Tmp" wide
		$a9 = "HDESK Bot" wide
		$a10 = "HDESK bot" wide
		$a11 = "CURSOR: %u, %u"
		$b1 = { 83 7C 24 ?? 00 75 ?? 83 7C 24 ?? 00 75 ?? [1] 8B 0D [4] 8B 44 24 }

	condition:
		6 of them
}