import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpc2 : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "2ed6d74e-2b95-5c70-807a-4da5e62f5853"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/SharpC2/SharpC2"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L480-L504"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f145c6061a4babb006acb84b3dd16a9fe7ce5819c9a656f0a947119016cf992b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "62b9ee4f-1436-4098-9bc1-dd61b42d8b81" ascii wide
		$typelibguid0up = "62B9EE4F-1436-4098-9BC1-DD61B42D8B81" ascii wide
		$typelibguid1lo = "d2f17a91-eb2d-4373-90bf-a26e46c68f76" ascii wide
		$typelibguid1up = "D2F17A91-EB2D-4373-90BF-A26E46C68F76" ascii wide
		$typelibguid2lo = "a9db9fcc-7502-42cd-81ec-3cd66f511346" ascii wide
		$typelibguid2up = "A9DB9FCC-7502-42CD-81EC-3CD66F511346" ascii wide
		$typelibguid3lo = "ca6cc2ee-75fd-4f00-b687-917fa55a4fae" ascii wide
		$typelibguid3up = "CA6CC2EE-75FD-4F00-B687-917FA55A4FAE" ascii wide
		$typelibguid4lo = "a1167b68-446b-4c0c-a8b8-2a7278b67511" ascii wide
		$typelibguid4up = "A1167B68-446B-4C0C-A8B8-2A7278B67511" ascii wide
		$typelibguid5lo = "4d8c2a88-1da5-4abe-8995-6606473d7cf1" ascii wide
		$typelibguid5up = "4D8C2A88-1DA5-4ABE-8995-6606473D7CF1" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}