rule ELASTIC_Windows_Trojan_Fabookie_024F8759 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Fabookie (Windows.Trojan.Fabookie)"
		author = "Elastic Security"
		id = "024f8759-aaed-40fb-8052-35b58cf69f4e"
		date = "2023-06-22"
		modified = "2023-07-10"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Fabookie.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "6c6345c6f0a5beadc4616170c87ec8a577de185d53345581e1b00e72af24c13e"
		logic_hash = "9477406b718c6489161cf4636be66c4f72df923b9c5a7ee4069ef6a9552de485"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0f5be9523a9a3f570e36ed8bbc9d113ffc8a40f868d5826e8b236d65f66e186b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 48 89 C2 4D 33 C0 4D 33 C9 C7 44 24 20 02 00 00 80 }
		$a2 = { C7 C2 80 84 1E 00 41 C7 C0 00 10 00 00 41 C7 C1 04 00 00 00 48 8B 44 24 }

	condition:
		all of them
}