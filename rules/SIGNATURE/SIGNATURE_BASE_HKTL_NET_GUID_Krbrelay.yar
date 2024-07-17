rule SIGNATURE_BASE_HKTL_NET_GUID_Krbrelay : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "3f59986c-8bd8-5e70-b3eb-038247d1ccd7"
		date = "2022-11-21"
		modified = "2023-04-06"
		reference = "https://github.com/cube0x0/KrbRelay"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L5013-L5029"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "1cab7949f922e286ed68826cc8f0028cabdc10bd328398b6d2517ad467be50b8"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "ed839154-90d8-49db-8cdd-972d1a6b2cfd" ascii wide
		$typelibguid0up = "ED839154-90D8-49DB-8CDD-972D1A6B2CFD" ascii wide
		$typelibguid1lo = "3b47eebc-0d33-4e0b-bab5-782d2d3680af" ascii wide
		$typelibguid1up = "3B47EEBC-0D33-4E0B-BAB5-782D2D3680AF" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}