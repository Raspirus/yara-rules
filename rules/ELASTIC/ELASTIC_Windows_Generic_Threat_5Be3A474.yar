
rule ELASTIC_Windows_Generic_Threat_5Be3A474 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "5be3a474-d12f-489f-a2a7-87d29687e2e6"
		date = "2024-03-04"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2943-L2961"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b902954d634307260d5bd8fb6248271f933c1cbc649aa2073bf05e79c1aedb66"
		logic_hash = "0f0f46e3bdebb47a4f43ccb64d65ab1e15d68d38c117cb25e5723ec16e7e0758"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8b220ea86ad3bbdcf6e2f976dc0bb84c1eb8cb1f3ad46ab5c9d19289952c912b"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 51 53 56 57 8B F9 33 F6 8D 5F 02 66 8B 07 83 C7 02 66 3B C6 75 F5 8A 01 2B FB D1 FF 8D 5F FF 85 DB 7E 23 0F B6 F8 83 C1 02 66 8B 01 8D 49 02 66 2B C7 C7 45 FC 00 08 00 00 66 2B 45 FC }

	condition:
		all of them
}