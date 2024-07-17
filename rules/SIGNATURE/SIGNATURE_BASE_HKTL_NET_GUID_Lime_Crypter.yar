rule SIGNATURE_BASE_HKTL_NET_GUID_Lime_Crypter : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "484c7a15-7ab2-57d3-848c-0fddff753d52"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/NYAN-x-CAT/Lime-Crypter"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1933-L1947"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "45a47b8ed17b157e22e6819f08a245aca2930d276b52d781fbbc82bcfb184ab4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "f93c99ed-28c9-48c5-bb90-dd98f18285a6" ascii wide
		$typelibguid0up = "F93C99ED-28C9-48C5-BB90-DD98F18285A6" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}