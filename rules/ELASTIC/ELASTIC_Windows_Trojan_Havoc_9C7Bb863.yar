
rule ELASTIC_Windows_Trojan_Havoc_9C7Bb863 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Havoc (Windows.Trojan.Havoc)"
		author = "Elastic Security"
		id = "9c7bb863-b6c2-4d5f-ae50-0fd900f1d4eb"
		date = "2023-04-28"
		modified = "2023-06-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Havoc.yar#L37-L56"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "261b92d9e8dcb9d0abf1627b791831ec89779f2b7973b1926c6ec9691288dd57"
		logic_hash = "c1245c38c54b0a72fb335680d9ea191390e4e2fe7e47a3ed776878c5e01a3e16"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "cda55a9e65badb984e71778b081929db2bdef223792b78bba32b2259757f1348"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 56 48 89 E6 48 83 E4 F0 48 83 EC 20 E8 0F 00 00 00 48 89 F4 5E C3 }
		$a2 = { 65 48 8B 04 25 60 00 00 00 }

	condition:
		all of them
}