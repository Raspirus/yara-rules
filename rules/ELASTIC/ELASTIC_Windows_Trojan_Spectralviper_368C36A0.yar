rule ELASTIC_Windows_Trojan_Spectralviper_368C36A0 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Spectralviper (Windows.Trojan.SpectralViper)"
		author = "Elastic Security"
		id = "368c36a0-d8ec-4cd6-92b3-193907898dc1"
		date = "2023-05-10"
		modified = "2023-05-10"
		reference = "https://www.elastic.co/security-labs/elastic-charms-spectralviper"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_SpectralViper.yar#L29-L53"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d1c32176b46ce171dbce46493eb3c5312db134b0a3cfa266071555c704e6cff8"
		logic_hash = "6182bde93e18dc6a83a94b50b193f5f29ed9abfa89b53c290818e7dab5bbb334"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "cfe4df5390a625d59f1c30775fe26119707a296feb1a205f3df734a4c0fcc25c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 18 48 89 4F D8 0F 10 40 20 0F 11 47 E0 0F 10 40 30 0F 11 47 F0 48 8D }
		$a2 = { 24 27 48 83 C4 28 5B 5D 5F 5E C3 56 57 53 48 83 EC 20 48 89 CE 48 }
		$a3 = { C7 84 C9 0F 45 C7 EB 86 48 8B 44 24 28 48 83 C4 30 5B 5F 5E C3 48 83 }
		$s1 = { 40 53 48 83 EC 20 48 8B 01 48 8B D9 48 8B 51 10 48 8B 49 08 FF D0 48 89 43 18 B8 04 00 00 }
		$s2 = { 40 53 48 83 EC 20 48 8B 01 48 8B D9 48 8B 49 08 FF D0 48 89 43 10 B8 04 00 00 00 48 83 C4 20 5B }
		$s3 = { 48 83 EC 28 4C 8B 41 18 4C 8B C9 48 B8 AB AA AA AA AA AA AA AA 48 F7 61 10 48 8B 49 08 48 C1 EA }

	condition:
		2 of ($a*) or any of ($s*)
}