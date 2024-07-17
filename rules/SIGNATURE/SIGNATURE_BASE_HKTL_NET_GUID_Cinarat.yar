rule SIGNATURE_BASE_HKTL_NET_GUID_Cinarat : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "c6b4c919-0fc6-5096-b29b-963142a2c831"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/wearelegal/CinaRAT"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L396-L412"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "10b086a6472ebad3bc3ab3fe41fb1869632aa94f4fe44446fa1fa7d97abf3ce6"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "8586f5b1-2ef4-4f35-bd45-c6206fdc0ebc" ascii wide
		$typelibguid0up = "8586F5B1-2EF4-4F35-BD45-C6206FDC0EBC" ascii wide
		$typelibguid1lo = "fe184ab5-f153-4179-9bf5-50523987cf1f" ascii wide
		$typelibguid1up = "FE184AB5-F153-4179-9BF5-50523987CF1F" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}