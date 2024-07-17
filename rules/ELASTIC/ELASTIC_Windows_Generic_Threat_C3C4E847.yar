rule ELASTIC_Windows_Generic_Threat_C3C4E847 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "c3c4e847-ef6f-430d-9778-d48326fb4eb0"
		date = "2024-01-17"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1526-L1544"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "86b37f0b2d9d7a810b5739776b4104f1ded3a1228c4ec2d104d26d8eb26aa7ba"
		logic_hash = "fa147abf7aa872f409e7684c4c60485fc58f57543062573526e56ff9866f8dfe"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "017a8ec014fed493018cff128b973bb648dbb9a0d1bede313d237651d3f6531a"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 2E 3F 41 56 3F 24 5F 52 65 66 5F 63 6F 75 6E 74 40 55 41 70 69 44 61 74 61 40 40 40 73 74 64 40 40 }

	condition:
		all of them
}