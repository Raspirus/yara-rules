import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Neo_Confuserex : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "d73117a6-4512-5545-a4f4-72d8cf708340"
		date = "2021-01-21"
		modified = "2023-04-06"
		reference = "https://github.com/XenocodeRCE/neo-ConfuserEx"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4507-L4521"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "2394b2a7098b284b18bf9fcda6ca26b34ae0143f8bd146578cc9c2d68df0741c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "e98490bb-63e5-492d-b14e-304de928f81a" ascii wide
		$typelibguid0up = "E98490BB-63E5-492D-B14E-304DE928F81A" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}