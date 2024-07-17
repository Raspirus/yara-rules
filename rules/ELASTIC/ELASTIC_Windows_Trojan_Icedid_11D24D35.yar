rule ELASTIC_Windows_Trojan_Icedid_11D24D35 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Icedid (Windows.Trojan.IcedID)"
		author = "Elastic Security"
		id = "11d24d35-6bff-4fac-83d8-4d152aa0be57"
		date = "2022-02-16"
		modified = "2022-04-06"
		reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_IcedID.yar#L101-L121"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b8d794f6449669ff2d11bc635490d9efdd1f4e92fcb3be5cdb4b40e4470c0982"
		logic_hash = "4a5d0f37e3e80e370ae79fd45256dbd274ed8f8bcd021e8d6f95a0bc0bc5321f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "155e5df0f3f598cdc21e5c85bcf21c1574ae6788d5f7e0058be823c71d06c21e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "C:\\Users\\user\\source\\repos\\anubis\\bin\\RELEASE\\loader_dll_64.pdb" ascii fullword
		$a2 = "loader_dll_64.dll" ascii fullword

	condition:
		1 of ($a*)
}