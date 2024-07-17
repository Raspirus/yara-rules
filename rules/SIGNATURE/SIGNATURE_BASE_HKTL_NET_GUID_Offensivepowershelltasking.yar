rule SIGNATURE_BASE_HKTL_NET_GUID_Offensivepowershelltasking : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "d221e24d-a2ef-51e2-95bf-4b91b438d9cf"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/leechristensen/OffensivePowerShellTasking"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2193-L2209"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "6de43b8349ff5f0e87d91e522be802a5dd18745441ffb76dcef63d2f1cd25332"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "d432c332-3b48-4d06-bedb-462e264e6688" ascii wide
		$typelibguid0up = "D432C332-3B48-4D06-BEDB-462E264E6688" ascii wide
		$typelibguid1lo = "5796276f-1c7a-4d7b-a089-550a8c19d0e8" ascii wide
		$typelibguid1up = "5796276F-1C7A-4D7B-A089-550A8C19D0E8" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}