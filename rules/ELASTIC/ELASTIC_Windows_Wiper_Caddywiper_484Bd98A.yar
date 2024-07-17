rule ELASTIC_Windows_Wiper_Caddywiper_484Bd98A : FILE MEMORY
{
	meta:
		description = "Detects Windows Wiper Caddywiper (Windows.Wiper.CaddyWiper)"
		author = "Elastic Security"
		id = "484bd98a-543f-42de-a58c-fe9c7b5605a3"
		date = "2022-03-14"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Wiper_CaddyWiper.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a294620543334a721a2ae8eaaf9680a0786f4b9a216d75b55cfd28f39e9430ea"
		logic_hash = "f473673afc211b02328f4e9d88e709acd95bf4b1fa565f5aca972b92324bf589"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "de16515a72cd1f7b4d7ee46a4fafde07cf224c2b6df9037bcd20ab4d39181fa8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { C6 45 AC 43 C6 45 AD 3A C6 45 AE 5C C6 45 AF 55 C6 45 B0 73 C6 45 B1 65 C6 45 B2 72 C6 45 B3 73 }
		$a2 = { C6 45 E0 44 C6 45 E1 3A C6 45 E2 5C }
		$a3 = { C6 45 9C 6E C6 45 9D 65 C6 45 9E 74 C6 45 9F 61 C6 45 A0 70 C6 45 A1 69 C6 45 A2 33 C6 45 A3 32 }
		$s1 = "DsRoleGetPrimaryDomainInformation"

	condition:
		all of them
}