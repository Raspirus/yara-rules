rule ELASTIC_Windows_Trojan_Redlinestealer_983Cd7A7 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Redlinestealer (Windows.Trojan.RedLineStealer)"
		author = "Elastic Security"
		id = "983cd7a7-4e7b-413f-b859-b5cbfbf14ae6"
		date = "2024-03-27"
		modified = "2024-05-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_RedLineStealer.yar#L188-L208"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "7aa20c57b8815dd63c8ae951e1819c75b5d2deec5aae0597feec878272772f35"
		logic_hash = "2104bad5ec42bc72ec611607a53086a85359bdb4bf084d7377e9a8e234b0e928"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "6dd74c3b67501506ee43340c07b53ddb94e919d27ad96f55eb4eff3de1470699"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$decrypt_config_bytes = { 72 ?? ?? ?? 70 80 ?? ?? ?? 04 72 ?? ?? ?? 70 80 ?? ?? ?? 04 72 ?? ?? ?? 70 80 ?? ?? ?? 04 72 ?? ?? ?? 70 80 ?? ?? ?? 04 [0-6] 2A }
		$str1 = "net.tcp://" wide
		$str2 = "\\Discord\\Local Storage\\leveldb" wide

	condition:
		all of them
}