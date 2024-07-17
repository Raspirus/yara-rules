
rule ELASTIC_Windows_Trojan_Trickbot_E7932501 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Trickbot (Windows.Trojan.Trickbot)"
		author = "Elastic Security"
		id = "e7932501-66bf-4713-b10e-bcda29f4b901"
		date = "2021-03-28"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Trickbot.yar#L117-L134"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "f82704a408a0cf1def2a5926dc4c02fa56afea1422c88ba41af50d44c60edb07"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ae31b49266386a6cf42289a08da4a20fc1330096be1dae793de7b7230225bfc7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 24 0C 01 00 00 00 85 C0 7C 2F 3B 46 24 7D 2A 8B 4E 20 8D 04 }

	condition:
		all of them
}