import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Anti_Analysis : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "bd527841-065e-57e9-b70e-c9d232072f1b"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/NYAN-x-CAT/Anti-Analysis"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1863-L1877"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "60d7b68aabc6819c8bbc3adfa069f624df4ba3fecd7548841a8cd2f4415fd1a7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "3092c8df-e9e4-4b75-b78e-f81a0058a635" ascii wide
		$typelibguid0up = "3092C8DF-E9E4-4B75-B78E-F81A0058A635" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}