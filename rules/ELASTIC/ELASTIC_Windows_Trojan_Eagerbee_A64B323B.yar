rule ELASTIC_Windows_Trojan_Eagerbee_A64B323B : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Eagerbee (Windows.Trojan.EagerBee)"
		author = "Elastic Security"
		id = "a64b323b-60b6-49b9-99d2-82a336fe304e"
		date = "2023-09-04"
		modified = "2023-09-20"
		reference = "https://www.elastic.co/security-labs/introducing-the-ref5961-intrusion-set"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_EagerBee.yar#L23-L45"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "339e4fdbccb65b0b06a1421c719300a8da844789a2016d58e8ce4227cb5dc91b"
		logic_hash = "e1c25cf8ce0ff434727c9104c6b79110ff5cfa84eb3e939119fd05cf676727c6"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "5109ec213a2ac1a1d920f3a9753bed97d038b226775996002511df5dc0b6de9c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$dexor_config_file = { 48 FF C0 8D 51 FF 44 30 00 49 03 C4 49 2B D4 ?? ?? 48 8D 4F 01 48 }
		$parse_config = { 80 7C 14 20 3A ?? ?? ?? ?? ?? ?? 45 03 C4 49 03 D4 49 63 C0 48 3B C1 }
		$parse_proxy1 = { 44 88 7C 24 31 44 88 7C 24 32 48 F7 D1 C6 44 24 33 70 C6 44 24 34 3D 88 5C 24 35 48 83 F9 01 }
		$parse_proxy2 = { 33 C0 48 8D BC 24 F0 00 00 00 49 8B CE F2 AE 8B D3 48 F7 D1 48 83 E9 01 48 8B F9 }

	condition:
		2 of them
}