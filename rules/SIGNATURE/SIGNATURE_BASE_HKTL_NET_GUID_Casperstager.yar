rule SIGNATURE_BASE_HKTL_NET_GUID_Casperstager : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "0ad18d2b-b7cc-5316-a8e8-b05d4439b8e1"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/ustayready/CasperStager"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2965-L2981"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "6ac00affab78024da7a1cfa6e6fd43c6a8f3c7fec59499a85c1330ee593488eb"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "c653a9f2-0939-43c8-9b93-fed5e2e4c7e6" ascii wide
		$typelibguid0up = "C653A9F2-0939-43C8-9B93-FED5E2E4C7E6" ascii wide
		$typelibguid1lo = "48dfc55e-6ae5-4a36-abef-14bc09d7510b" ascii wide
		$typelibguid1up = "48DFC55E-6AE5-4A36-ABEF-14BC09D7510B" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}