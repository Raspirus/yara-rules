
rule ELASTIC_Windows_Generic_Threat_347F9F54 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "347f9f54-b9a6-4d40-9627-d3cef78f13eb"
		date = "2023-12-18"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L202-L220"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "45a051651ce1edddd33ecef09bb0fbb978adec9044e64f786b13ed81cabf6a3f"
		logic_hash = "63df388393a45ffec68ba01ae6d7707b6d5277e0162ded6e631c1f76ad76b711"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "860f951db43fa3389c5057f7329b5d13d9347b6e04e1363dd0a8060d5a131991"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 83 EC 10 FF 75 0C 80 65 FC 00 8D 45 F0 C6 45 F0 43 50 C6 45 F1 6F FF 75 08 C6 45 F2 6E C6 45 F3 6E C6 45 F4 65 C6 45 F5 63 C6 45 F6 74 C6 45 F7 47 C6 45 F8 72 C6 45 F9 6F C6 45 FA 75 }

	condition:
		all of them
}