import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Nashavm : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "3abbf636-01f4-547a-98c0-d7bfec07e31a"
		date = "2021-01-21"
		modified = "2023-04-06"
		reference = "https://github.com/Mrakovic-ORG/NashaVM"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4947-L4961"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "4046e8183ee2bcf95893f9a438f13aec9afa99e252029888830a0bf81dac2f6f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "f9e63498-6e92-4afd-8c13-4f63a3d964c3" ascii wide
		$typelibguid0up = "F9E63498-6E92-4AFD-8C13-4F63A3D964C3" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}