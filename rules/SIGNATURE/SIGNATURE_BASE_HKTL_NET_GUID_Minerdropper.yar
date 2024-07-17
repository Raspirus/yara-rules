rule SIGNATURE_BASE_HKTL_NET_GUID_Minerdropper : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "607f72df-b0c1-53df-bf2c-592f55cbfcb7"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/DylanAlloy/MinerDropper"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2459-L2475"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ce050b7dd0a9bae5737f5170a8656f737754e6c96e64bca2ceab9b030c4cdddb"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "46a7af83-1da7-40b2-9d86-6fd6223f6791" ascii wide
		$typelibguid0up = "46A7AF83-1DA7-40B2-9D86-6FD6223F6791" ascii wide
		$typelibguid1lo = "8433a693-f39d-451b-955b-31c3e7fa6825" ascii wide
		$typelibguid1up = "8433A693-F39D-451B-955B-31C3E7FA6825" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}