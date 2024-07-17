
rule ELASTIC_Windows_Trojan_Sliver_1Dd6D9C2 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Sliver (Windows.Trojan.Sliver)"
		author = "Elastic Security"
		id = "1dd6d9c2-026e-4140-b804-b56e07c72ac2"
		date = "2023-05-10"
		modified = "2023-06-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Sliver.yar#L42-L61"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "dc508a3e9ea093200acfc1ceebebb2b56686f4764fd8c94ab8c58eec7ee85c8b"
		logic_hash = "5ef70322a6ee3dec609d2881b7624d25bc0297a2e6f43ac60834745e6a258cf3"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "fb676adf8b9d10d1e151bfb2a6a7e132cff4e55c20f454201a4ece492902fc35"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { B7 11 49 89 DB C1 EB 10 41 01 DA 66 45 89 11 4C 89 DB EB B6 4D 8D }
		$a2 = { 36 2E 33 20 62 75 69 6C 48 39 }

	condition:
		all of them
}