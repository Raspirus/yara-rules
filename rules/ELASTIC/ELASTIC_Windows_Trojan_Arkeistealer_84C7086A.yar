
rule ELASTIC_Windows_Trojan_Arkeistealer_84C7086A : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Arkeistealer (Windows.Trojan.ArkeiStealer)"
		author = "Elastic Security"
		id = "84c7086a-abc3-4b97-b325-46a078b90a95"
		date = "2022-02-17"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_ArkeiStealer.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "708d9fb40f49192d4bf6eff62e0140c920a7eca01b9f78aeaf558bef0115dbe2"
		logic_hash = "b7129094389f789f0b43f0da54645c24a6d1149f53d6536c14714e3ff44f935b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f1d701463b0001de8996b30d2e36ddecb93fe4ca2a1a26fc4fcdaeb0aa3a3d6d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 01 89 55 F4 8B 45 F4 3B 45 10 73 31 8B 4D 08 03 4D F4 0F BE 19 8B }

	condition:
		all of them
}