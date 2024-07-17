rule ELASTIC_Windows_Trojan_Privateloader_96Ac2734 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Privateloader (Windows.Trojan.PrivateLoader)"
		author = "Elastic Security"
		id = "96ac2734-e36c-4ce2-bb40-b6bd77694333"
		date = "2023-01-03"
		modified = "2023-02-01"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_PrivateLoader.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "077225467638a420cf29fb9b3f0241416dcb9ed5d4ba32fdcf2bf28f095740bb"
		logic_hash = "9f96f1c54853866e124d0996504e6efd3d154111390617999cc10520d7f68fe6"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "029056908abef6c3ceecf7956e64a6d25b67c391f699516b3202d2aa3733f15a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$xor_decrypt = { 0F 28 85 ?? ?? FF FF 66 0F EF ?? ?? FE FF FF 0F 29 85 ?? ?? FF FF 0F 28 85 ?? ?? FF FF }
		$str0 = "https://ipinfo.io/" wide
		$str1 = "Content-Type: application/x-www-form-urlencoded" wide
		$str2 = "https://db-ip.com/" wide

	condition:
		all of ($str*) and #xor_decrypt>3
}