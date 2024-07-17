rule ELASTIC_Windows_Trojan_Jesterstealer_8F657F58 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Jesterstealer (Windows.Trojan.JesterStealer)"
		author = "Elastic Security"
		id = "8f657f58-57e0-4e5f-9223-00bfade16605"
		date = "2022-02-28"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_JesterStealer.yar#L27-L45"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "10c3846867f70dd26c5a54332ed22070c9e5e0e4f52f05fdae12ead801f7933b"
		logic_hash = "20a0d8be9c25d50d4dddd455ecb9739f772f57e988855c7fc2df597b2f67585b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "aabf8633e853f623b75e8a354378d110442e724425f623b8c553d3522ca5dad6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 27 01 00 00 00 96 08 0B 80 79 01 6C 02 A4 27 01 00 00 00 96 08 }

	condition:
		all of them
}