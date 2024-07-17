rule SIGNATURE_BASE_HKTL_NET_GUID_Darkeye : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "5dc6702f-a398-5be2-9df8-9a2ddc636a1f"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/K1ngSoul/DarkEye"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L104-L118"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ce1f7f9bb621ebc2bc0701084436d1932f33071483aac9c487e00ca911da4ddd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "0bdb9c65-14ed-4205-ab0c-ea2151866a7f" ascii wide
		$typelibguid0up = "0BDB9C65-14ED-4205-AB0C-EA2151866A7F" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}