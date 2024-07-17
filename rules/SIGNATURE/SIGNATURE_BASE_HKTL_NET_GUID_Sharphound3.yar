rule SIGNATURE_BASE_HKTL_NET_GUID_Sharphound3 : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "58001912-88a1-527d-9d3e-d7c376a1fce4"
		date = "2020-12-29"
		modified = "2023-04-06"
		reference = "https://github.com/BloodHoundAD/SharpHound3"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4214-L4228"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "0350505aa796cccc56092fb835269c5aad6de0096bbfc5d1608113e11827951a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "a517a8de-5834-411d-abda-2d0e1766539c" ascii wide
		$typelibguid0up = "A517A8DE-5834-411D-ABDA-2D0E1766539C" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}