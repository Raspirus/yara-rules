rule ELASTIC_Windows_Hacktool_Dcsyncer_425579C5 : FILE MEMORY
{
	meta:
		description = "MGIxY2/05+FBDTur++++0OUs"
		author = "Elastic Security"
		id = "425579c5-496f-4e08-a7e3-bf56e622aa21"
		date = "2021-09-15"
		modified = "2022-01-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_Dcsyncer.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "af7dbc84efeb186006d75d095f54a266f59e6b2348d0c20591da16ae7b7d509a"
		logic_hash = "b0330adf1d4420ddf1f302974d2e4179f52ab1c8dc2f294ddf52286d714e0463"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f6a0c028323be41f6ec90af8a7ea8587fee6985ddefdbcdd24351cb615f756a2"
		threat_name = "Windows.Hacktool.Dcsyncer"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "[x] dcsync: Error in ProcessGetNCChangesReply" wide fullword
		$a2 = "[x] getDCBind: RPC Exception 0x%08x (%u)" wide fullword
		$a3 = "[x] getDomainAndUserInfos: DomainControllerInfo: 0x%08x (%u)" wide fullword
		$a4 = "[x] ProcessGetNCChangesReply_decrypt: Checksums don't match (C:0x%08x - R:0x%08x)" wide fullword

	condition:
		any of them
}