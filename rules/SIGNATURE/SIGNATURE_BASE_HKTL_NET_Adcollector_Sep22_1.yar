
rule SIGNATURE_BASE_HKTL_NET_Adcollector_Sep22_1 : FILE
{
	meta:
		description = "Detects ADCollector Tool - a lightweight tool to quickly extract valuable information from the Active Directory environment for both attacking and defending"
		author = "Florian Roth (Nextron Systems)"
		id = "48b376e4-752b-523e-b34e-65b6944c33fb"
		date = "2022-09-15"
		modified = "2023-12-05"
		reference = "https://github.com/dev-2null/ADCollector"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_names.yar#L55-L75"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "66d5363e885378c442e7532f69d4c36618d7a0f5dbe67490631d1ed5078d3fba"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "241390219a0a773463601ca68b77af97453c20af00a66492a7a78c04d481d338"
		hash2 = "cc086eb7316e68661e3d547b414890d5029c5cc460134d8b628f4b0be7f27fb3"

	strings:
		$x1 = "ADCollector.exe --SPNs --Term key --Acls 'CN=Domain Admins,CN=Users,DC=lab,DC=local'" wide fullword
		$s1 = "ADCollector.exe" wide fullword
		$s2 = "ENCRYPTED_TEXT_PASSWORD_ALLOWED" ascii fullword
		$s3 = "\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf" wide
		$s4 = "[-] Password Does Not Expire Accounts:" wide
		$s5 = "  * runAs:       {0}" wide fullword

	condition:
		uint16(0)==0x5a4d and filesize <300KB and (1 of ($x*) or 3 of them )
}