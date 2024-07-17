rule SIGNATURE_BASE_HKTL_NET_GUID_Educationalrat : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "b1d54bea-a6c4-5c57-9ee1-7438d503b01d"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/securesean/EducationalRAT"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1184-L1198"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ad6baa993ba3da60233da39ec55b10ab0fe3b2ca52882972b54c7d199e7b6abb"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "8a18fbcf-8cac-482d-8ab7-08a44f0e278e" ascii wide
		$typelibguid0up = "8A18FBCF-8CAC-482D-8AB7-08A44F0E278E" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}