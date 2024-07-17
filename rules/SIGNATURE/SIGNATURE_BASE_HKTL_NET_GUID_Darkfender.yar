import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Darkfender : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "0aea5e05-7788-5581-8bcc-d2e75a291dd9"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/0xyg3n/DarkFender"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2423-L2437"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "97cc537dca2f8559edf7ca44124a2056194aceee9327fa097674bccdeb0316df"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "12fdf7ce-4a7c-41b6-9b32-766ddd299beb" ascii wide
		$typelibguid0up = "12FDF7CE-4A7C-41B6-9B32-766DDD299BEB" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}