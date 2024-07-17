rule SIGNATURE_BASE_HKTL_NET_GUID_CVE_2019_1064 : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "4640e874-faa4-58dc-a3f3-18246a343f15"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/RythmStick/CVE-2019-1064"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3198-L3212"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "d78b15454af39bca869c07a78550d2b3827ecdd03bcf02a8614e0c8247fcf5c1"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "ff97e98a-635e-4ea9-b2d0-1a13f6bdbc38" ascii wide
		$typelibguid0up = "FF97E98A-635E-4EA9-B2D0-1A13F6BDBC38" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}