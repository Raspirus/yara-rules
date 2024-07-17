import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Externalc2 : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "1bbdfbb9-a3e8-5ffe-9db9-b50937e6a14d"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/ryhanson/ExternalC2"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L136-L152"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "90d05afe605d90dd61e8f5095125eb30c2b7a781b90b9ab42ee8391823b53b83"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "7266acbb-b10d-4873-9b99-12d2043b1d4e" ascii wide
		$typelibguid0up = "7266ACBB-B10D-4873-9B99-12D2043B1D4E" ascii wide
		$typelibguid1lo = "5d9515d0-df67-40ed-a6b2-6619620ef0ef" ascii wide
		$typelibguid1up = "5D9515D0-DF67-40ED-A6B2-6619620EF0EF" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}