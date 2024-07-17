rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpire : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "32bdaa0f-3afc-5e0e-a20f-e21f33909af7"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/0xbadjuju/Sharpire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3667-L3681"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f8ddf85c279c6ea4a2db679a0d5c816837e8bd91f1f6e15787dd34463483fc85"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "39b75120-07fe-4833-a02e-579ff8b68331" ascii wide
		$typelibguid0up = "39B75120-07FE-4833-A02E-579FF8B68331" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}