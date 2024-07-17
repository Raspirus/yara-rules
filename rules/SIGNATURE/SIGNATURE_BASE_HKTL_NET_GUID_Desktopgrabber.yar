rule SIGNATURE_BASE_HKTL_NET_GUID_Desktopgrabber : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "7db07291-d6d4-5527-a879-27f899dbd6fe"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/NYAN-x-CAT/DesktopGrabber"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1120-L1134"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "150a2f89eee5e5e0fa77c42b004e170d8706db69e02293f297376933ec03d1be"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "e6aa0cd5-9537-47a0-8c85-1fbe284a4380" ascii wide
		$typelibguid0up = "E6AA0CD5-9537-47A0-8C85-1FBE284A4380" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}