rule ELASTIC_Windows_Trojan_Netwire_6A7Df287 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Netwire (Windows.Trojan.Netwire)"
		author = "Elastic Security"
		id = "6a7df287-1656-4779-9a96-c0ab536ae86a"
		date = "2021-06-28"
		modified = "2021-08-23"
		reference = "https://www.elastic.co/security-labs/netwire-dynamic-configuration-extraction"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Netwire.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e6f446dbefd4469b6c4d24988dd6c9ccd331c8b36bdbc4aaf2e5fc49de2c3254"
		logic_hash = "d5f36e2a81cf0a9037267d39266b4c31ca9c07b05fb9772e296aeac2da6051a5"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "85051a0b94da4388eaead4c4f4b2d16d4a5eb50c3c938b3daf5c299c9c12f1e6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 0F B6 74 0C 10 89 CF 29 C7 F7 C6 DF 00 00 00 74 09 41 89 F3 88 5C }

	condition:
		all of them
}