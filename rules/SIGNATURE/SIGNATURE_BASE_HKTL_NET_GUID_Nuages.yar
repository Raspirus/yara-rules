import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Nuages : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "5ad947e2-bd71-50d4-9bbf-4d018c7ff36a"
		date = "2020-12-29"
		modified = "2023-04-06"
		reference = "https://github.com/p3nt4/Nuages"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4182-L4196"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "cf417eb45867b6fe77cf229688b3c210814a902949840ed946a9d9cff8c8a3d7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "e9e80ac7-4c13-45bd-9bde-ca89aadf1294" ascii wide
		$typelibguid0up = "E9E80AC7-4C13-45BD-9BDE-CA89AADF1294" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}