rule ELASTIC_Macos_Trojan_Bundlore_C8Ad7Edd : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Bundlore (MacOS.Trojan.Bundlore)"
		author = "Elastic Security"
		id = "c8ad7edd-4233-44ce-a4e5-96dfc3504f8a"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Bundlore.yar#L141-L159"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d4915473e1096a82afdaee405189a0d0ae961bd11a9e5e9adc420dd64cb48c24"
		logic_hash = "be09b4bd612bb499044fe91ca4e1ab62405cf1e4d75b8e1da90e326d1c66e04f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c6a8a1d9951863d4277d297dd6ff8ad7b758ca2dfe16740265456bb7bb0fd7d0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 35 74 11 00 00 D5 80 35 6E 11 00 00 57 80 35 68 11 00 00 4C 80 35 62 11 00 00 }

	condition:
		all of them
}