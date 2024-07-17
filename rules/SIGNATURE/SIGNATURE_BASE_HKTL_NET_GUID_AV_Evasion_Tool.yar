rule SIGNATURE_BASE_HKTL_NET_GUID_AV_Evasion_Tool : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "d4257465-38a0-56b9-8402-b92e21b96cb0"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/1y0n/AV_Evasion_Tool"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1600-L1616"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "682d16cbef455680186ca9d17c3d24619e4b018cd7915cea4f0e2f2f0c843e98"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "1937ee16-57d7-4a5f-88f4-024244f19dc6" ascii wide
		$typelibguid0up = "1937EE16-57D7-4A5F-88F4-024244F19DC6" ascii wide
		$typelibguid1lo = "7898617d-08d2-4297-adfe-5edd5c1b828b" ascii wide
		$typelibguid1up = "7898617D-08D2-4297-ADFE-5EDD5C1B828B" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}