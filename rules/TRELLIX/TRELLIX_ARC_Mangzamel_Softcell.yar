rule TRELLIX_ARC_Mangzamel_Softcell : TROJAN FILE
{
	meta:
		description = "Rule to detect Mangzamel used in the SoftCell operation"
		author = "Marc Rivero | McAfee ATR Team"
		id = "b0473362-7e03-5127-aee5-b5a4f05bcc8e"
		date = "2019-06-25"
		modified = "2020-08-14"
		reference = "https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/APT/APT_Operation_SoftCell.yar#L145-L176"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "3666c645943eb8469096b8093c74e4d819299d3ffc2b99e37a506d8ef09e90c4"
		score = 75
		quality = 70
		tags = "TROJAN, FILE"
		rule_version = "v1"
		malware_type = "trojan"
		malware_family = "Trojan:W32/Mangzamel"
		actor_type = "Apt"
		actor_group = "Unknown"

	strings:
		$s1 = "Change Service Mode to user logon failure.code:%d" fullword ascii
		$s2 = "spoolsvs.exe" fullword wide
		$s3 = "System\\CurrentControlSet\\Services\\%s\\parameters\\%s" fullword ascii
		$s4 = "Please Correct [-s %s]" fullword ascii
		$s5 = "Please Correct [-m %s]" fullword ascii
		$op0 = { 59 8d 85 64 ff ff ff 50 c7 85 64 ff ff ff 94 }
		$op1 = { c9 c2 08 00 81 c1 30 34 00 00 e9 cf 9b ff ff 55 }
		$op2 = { 80 0f b6 b5 68 ff ff ff c1 e2 04 0b d6 0f b6 b5 }

	condition:
		uint16(0)==0x5a4d and filesize <300KB and (pe.imphash()=="ef64bb4aa42ef5a8a2e3858a636bce40" and all of them )
}