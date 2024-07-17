rule ELASTIC_Windows_Trojan_Deimos_F53Aee03 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Deimos (Windows.Trojan.Deimos)"
		author = "Elastic Security"
		id = "f53aee03-74c3-4b40-8ae4-4f1bf35f88c8"
		date = "2021-09-18"
		modified = "2022-01-13"
		reference = "https://www.elastic.co/security-labs/going-coast-to-coast-climbing-the-pyramid-with-the-deimos-implant"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Deimos.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2c1941847f660a99bbc6de16b00e563f70d900f9dbc40c6734871993961d3d3e"
		logic_hash = "07675844a8790f8485b6545e7466cdef8ac4f92dec4cd8289aeaad2a0a448691"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "12a6d7f9e4f9a937bf1416443dd0d5ee556ac1f67d2b56ad35f9eac2ee6aac74"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "\\APPDATA\\ROAMING" wide fullword
		$a2 = "{\"action\":\"ping\",\"" wide fullword
		$a3 = "Deimos" ascii fullword

	condition:
		all of ($a*)
}