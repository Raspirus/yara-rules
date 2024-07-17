rule SIGNATURE_BASE_HKTL_NET_GUID_C_Sharp_R_A_T_Client : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "f5df8257-d202-58e3-9c4a-1dfc9dd52f2a"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/AdvancedHacker101/C-Sharp-R.A.T-Client"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3601-L3615"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "5e6a9db731caf7bc7ab79fa70c3f9bacaca8fa2d70deafe2a0b08ae4fac8a35b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "6d9e8852-e86c-4e36-9cb4-b3c3853ed6b8" ascii wide
		$typelibguid0up = "6D9E8852-E86C-4E36-9CB4-B3C3853ED6B8" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}