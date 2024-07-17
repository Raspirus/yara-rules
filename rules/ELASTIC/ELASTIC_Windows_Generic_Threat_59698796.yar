
rule ELASTIC_Windows_Generic_Threat_59698796 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "59698796-0022-486a-a743-6931745f38a0"
		date = "2024-03-04"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L3104-L3122"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "35f9698e9b9f611b3dd92466f18f97f4a8b4506ed6f10d4ac84303177f43522d"
		logic_hash = "59569049dbb09b7e15110fb8de1a146eb7fd606f116b4dd6c75ca973fb62296e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "9260d02c3e6b163fd376445bd2a9c084ed85a5dbaf0509e15fff4e9c3d147f19"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 81 EC B8 04 00 00 ?? ?? ?? ?? ?? 33 C5 89 45 FC 56 68 00 04 00 00 0F 57 C0 C7 45 F8 00 00 00 00 8D 85 58 FB FF FF C7 85 54 FB FF FF 24 00 00 00 6A 00 50 8B F1 0F 11 45 D8 0F 11 45 E8 }

	condition:
		all of them
}