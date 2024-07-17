rule ELASTIC_Windows_Trojan_Eagerbee_7029Ba21 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Eagerbee (Windows.Trojan.EagerBee)"
		author = "Elastic Security"
		id = "7029ba21-12ea-4120-911b-a36c4002409e"
		date = "2023-05-09"
		modified = "2023-06-13"
		reference = "https://www.elastic.co/security-labs/introducing-the-ref5961-intrusion-set"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_EagerBee.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "09005775fc587ac7bf150c05352e59dc01008b7bf8c1d870d1cea87561aa0b06"
		logic_hash = "874959361b14ba74e13e6e674da75c9bdb6b9475d8b286572825c940b41f679f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "26d0d10f7c503e284e2b24a9e273f880d2e152348dfdd44fb3fc8cb10aa57e2a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { C2 EB D6 0F B7 C2 48 8D 0C 80 41 8B 44 CB 14 41 2B 44 CB 0C 41 }
		$a2 = { C8 75 04 33 C0 EB 7C 48 63 41 3C 8B 94 08 88 00 00 00 48 03 D1 8B }

	condition:
		all of them
}