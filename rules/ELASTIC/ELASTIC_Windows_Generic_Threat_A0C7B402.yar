
rule ELASTIC_Windows_Generic_Threat_A0C7B402 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "a0c7b402-cee5-4da6-9a32-72b1a0ae0f8d"
		date = "2024-01-16"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1220-L1238"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5814d7712304800d92487b8e1108d20ad7b44f48910b1fb0a99e9b36baa4333a"
		logic_hash = "d0aa75debbefb301b9fc46ceca4944ae8c4b009118214a9589440b59089b853e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0ca7d91a97c12f4640dd367d19d8645dd1da713cfa62289c40f8c34202ddf256"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 89 E5 57 56 83 E4 F8 83 EC 20 8B 75 10 8B 7D 0C 89 E0 8D 4C 24 18 6A 05 6A 18 50 51 FF 75 08 68 BC 52 4D 90 E8 26 00 00 00 83 C4 18 85 FF 74 06 8B 4C 24 08 89 0F 85 F6 74 08 80 7C 24 15 00 }

	condition:
		all of them
}