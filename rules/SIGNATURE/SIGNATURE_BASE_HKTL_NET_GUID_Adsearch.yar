import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Adsearch : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "399ea06d-b36a-542b-bccc-8e8f935a35c6"
		date = "2021-01-21"
		modified = "2023-04-06"
		reference = "https://github.com/tomcarver16/ADSearch"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4555-L4569"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a35da6c6a396669928693b7d408f7d1021a7afc41dabfe521105254d69f23474"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "4da5f1b7-8936-4413-91f7-57d6e072b4a7" ascii wide
		$typelibguid0up = "4DA5F1B7-8936-4413-91F7-57D6E072B4A7" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}