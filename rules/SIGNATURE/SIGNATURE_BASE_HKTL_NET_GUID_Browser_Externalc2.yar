import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Browser_Externalc2 : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "8c309522-90e7-5f5a-b456-3a472756d397"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/mdsecactivebreach/Browser-ExternalC2"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2177-L2191"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "d5121396444c406049fcb6c24680a067341943a6982f67c7c5cd11947d3468bc"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "10a730cd-9517-42d5-b3e3-a2383515cca9" ascii wide
		$typelibguid0up = "10A730CD-9517-42D5-B3E3-A2383515CCA9" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}