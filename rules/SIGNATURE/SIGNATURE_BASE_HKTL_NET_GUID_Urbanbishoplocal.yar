rule SIGNATURE_BASE_HKTL_NET_GUID_Urbanbishoplocal : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "53b690ec-7d20-5e46-b368-b458ce56073d"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/slyd0g/UrbanBishopLocal"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L522-L536"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "0102e3ecbc13503858ad2119f206fa052caefdf557bbc62448c6da8c8b540de1"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "88b8515e-a0e8-4208-a9a0-34b01d7ba533" ascii wide
		$typelibguid0up = "88B8515E-A0E8-4208-A9A0-34B01D7BA533" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}