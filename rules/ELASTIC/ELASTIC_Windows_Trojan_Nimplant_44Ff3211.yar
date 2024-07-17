rule ELASTIC_Windows_Trojan_Nimplant_44Ff3211 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Nimplant (Windows.Trojan.Nimplant)"
		author = "Elastic Security"
		id = "44ff3211-1ba6-4c46-a990-b2419d88367e"
		date = "2023-06-23"
		modified = "2023-07-10"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Nimplant.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b56e20384f98e1d2417bb7dcdbfb375987dd075911b74ea7ead082494836b8f4"
		logic_hash = "ee519d8d722404ed440b385d283a41921bc34ee11f0e7273cdc074b377494c39"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "cb7f823b1621e49ffac42e8a3f90ca7f8bac7ae108ca20b9a0884548681d1f87"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "@NimPlant v"
		$a2 = ".Env_NimPlant."
		$a3 = "NimPlant.dll"

	condition:
		2 of them
}