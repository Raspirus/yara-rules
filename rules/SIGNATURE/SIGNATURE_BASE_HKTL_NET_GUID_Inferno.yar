rule SIGNATURE_BASE_HKTL_NET_GUID_Inferno : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "af2d9832-c7f9-5879-a19b-a3c4d91b8b3f"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/LimerBoy/Inferno"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3823-L3837"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a3255a00a1c2773d34e9e859c3394752ea6bfc164c4694a001c9a1c9b384756b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "26d498f7-37ae-476c-97b0-3761e3a919f0" ascii wide
		$typelibguid0up = "26D498F7-37AE-476C-97B0-3761E3A919F0" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}