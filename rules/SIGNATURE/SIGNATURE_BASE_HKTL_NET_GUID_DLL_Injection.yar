rule SIGNATURE_BASE_HKTL_NET_GUID_DLL_Injection : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "aec4fc28-9aa2-5eef-9fb1-d187a83a72b3"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/ihack4falafel/DLL-Injection"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L24-L38"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e98c60d2aefb38c550a67003304196e04c42c8cb0317208cf8ffaca175ca4ba0"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "3d7e1433-f81a-428a-934f-7cc7fcf1149d" ascii wide
		$typelibguid0up = "3D7E1433-F81A-428A-934F-7CC7FCF1149D" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}