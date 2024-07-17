import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Naga : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "3a9d3154-a8f1-57a4-8b61-498e2ebdfa42"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/byt3bl33d3r/Naga"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3246-L3262"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ff115b2817926a072088d5077d2969028b64ce2306920fa3278cfe842246e747"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "99428732-4979-47b6-a323-0bb7d6d07c95" ascii wide
		$typelibguid0up = "99428732-4979-47B6-A323-0BB7D6D07C95" ascii wide
		$typelibguid1lo = "a2c9488f-6067-4b17-8c6f-2d464e65c535" ascii wide
		$typelibguid1up = "A2C9488F-6067-4B17-8C6F-2D464E65C535" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}