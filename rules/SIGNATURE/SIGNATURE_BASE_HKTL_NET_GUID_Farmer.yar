import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Farmer : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "f69745b9-4ebd-547a-9af3-bc340b076e5d"
		date = "2023-03-22"
		modified = "2023-04-06"
		reference = "https://github.com/mdsecactivebreach/Farmer"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L5330-L5350"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "9f4c2cc503e8fd5b310f2c4b7d5914857612dab1435ca886bc7f8f362e822832"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "37da2573-d9b5-4fc2-ae11-ccb6130cea9f" ascii wide
		$typelibguid0up = "37DA2573-D9B5-4FC2-AE11-CCB6130CEA9F" ascii wide
		$typelibguid1lo = "49acf861-1c10-49a1-bf26-139a3b3a9227" ascii wide
		$typelibguid1up = "49ACF861-1C10-49A1-BF26-139A3B3A9227" ascii wide
		$typelibguid2lo = "9a6c028f-423f-4c2c-8db3-b3499139b822" ascii wide
		$typelibguid2up = "9A6C028F-423F-4C2C-8DB3-B3499139B822" ascii wide
		$typelibguid3lo = "1c896837-e729-46a9-92b9-3bbe7ac2c90d" ascii wide
		$typelibguid3up = "1C896837-E729-46A9-92B9-3BBE7AC2C90D" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}