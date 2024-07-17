import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Manager : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "eef65d2c-ddbc-50c3-a6a0-e7032a55e92d"
		date = "2021-01-21"
		modified = "2023-04-06"
		reference = "https://github.com/TheWover/Manager"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4489-L4505"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "cb6ef79b7430f0d7892c8c2819bc0d6f9493e0c74ca475b9f82b28a6b565dfb8"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "dda73ee9-0f41-4c09-9cad-8215abd60b33" ascii wide
		$typelibguid0up = "DDA73EE9-0F41-4C09-9CAD-8215ABD60B33" ascii wide
		$typelibguid1lo = "6a0f2422-d4d1-4b7e-84ad-56dc0fd2dfc5" ascii wide
		$typelibguid1up = "6A0F2422-D4D1-4B7E-84AD-56DC0FD2DFC5" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}