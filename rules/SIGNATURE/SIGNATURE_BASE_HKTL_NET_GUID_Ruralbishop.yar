import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Ruralbishop : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "8fd89465-1ecc-5eda-b2ab-273172ad945d"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/rasta-mouse/RuralBishop"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1999-L2013"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ee349395cbb2c692afcbdd0a6bce52d19762ec45b64cca684b60b148a1edd2d5"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "fe4414d9-1d7e-4eeb-b781-d278fe7a5619" ascii wide
		$typelibguid0up = "FE4414D9-1D7E-4EEB-B781-D278FE7A5619" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}