
rule ELASTIC_Windows_Generic_Threat_D62F1D01 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "d62f1d01-4e24-4a93-85ad-3a3886d5de2f"
		date = "2024-01-17"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1688-L1706"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "380892397b86f47ec5e6ed1845317bf3fd9c00d01f516cedfe032c0549eef239"
		logic_hash = "fd65eb56f3a48c37f83d3544c039d29c231cac1e2f8f07d176d709432a75a4c3"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f7736c8920092452ca795583a258ad8b1ffd79116bddde3cff5d06b3ddab31b6"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 51 53 56 8B 75 08 33 C0 57 8B FE AB AB AB 8B 7D 0C 8B 45 10 03 C7 89 45 FC 3B F8 73 3F 0F B7 1F 53 E8 01 46 00 00 59 66 3B C3 75 28 83 46 04 02 83 FB 0A 75 15 6A 0D 5B 53 E8 E9 45 00 }

	condition:
		all of them
}