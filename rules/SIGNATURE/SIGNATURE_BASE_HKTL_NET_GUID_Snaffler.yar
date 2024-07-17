rule SIGNATURE_BASE_HKTL_NET_GUID_Snaffler : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "d4b9a8c5-e0d9-5c85-af81-05f6e0f52bff"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/SnaffCon/Snaffler"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2531-L2547"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "13711b325cadf882be0aeb1073084193c73b9eec0f3a323d0cea9beeeb3d3cf5"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "2aa060b4-de88-4d2a-a26a-760c1cefec3e" ascii wide
		$typelibguid0up = "2AA060B4-DE88-4D2A-A26A-760C1CEFEC3E" ascii wide
		$typelibguid1lo = "b118802d-2e46-4e41-aac7-9ee890268f8b" ascii wide
		$typelibguid1up = "B118802D-2E46-4E41-AAC7-9EE890268F8B" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}