rule SIGNATURE_BASE_HKTL_NET_GUID_Amsiscanbufferbypass : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "12a15e61-30fb-50a3-a59b-39f9871444f0"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/rasta-mouse/AmsiScanBufferBypass"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L638-L652"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a064209a06c13506b2d2f3754aed30199b0f4f1c0ef4bc465d847a21b0917545"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "431ef2d9-5cca-41d3-87ba-c7f5e4582dd2" ascii wide
		$typelibguid0up = "431EF2D9-5CCA-41D3-87BA-C7F5E4582DD2" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}