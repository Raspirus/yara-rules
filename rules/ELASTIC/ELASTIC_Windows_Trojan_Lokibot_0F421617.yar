
rule ELASTIC_Windows_Trojan_Lokibot_0F421617 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Lokibot (Windows.Trojan.Lokibot)"
		author = "Elastic Security"
		id = "0f421617-df2b-4cb5-9d10-d984f6553012"
		date = "2021-07-20"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Lokibot.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "de6200b184832e7d3bfe00c193034192774e3cfca96120dc97ad6fed1e472080"
		logic_hash = "0076ccbe43ae77e3a80164d43832643f077e659a595fff01c87694e2274c5e86"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "9ff5d594428e4a5de84f0142dfa9f54cb75489192461deb978c70f1bdc88acda"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 08 8B CE 0F B6 14 38 D3 E2 83 C1 08 03 F2 48 79 F2 5F 8B C6 }

	condition:
		all of them
}