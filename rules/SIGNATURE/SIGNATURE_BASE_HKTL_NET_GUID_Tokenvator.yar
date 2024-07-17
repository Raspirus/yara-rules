import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Tokenvator : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "84ebb6b3-cf11-5172-95d4-d114bfeb0bc7"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/0xbadjuju/Tokenvator"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3214-L3228"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7bd3cc74ea70f247836ed4d0da9602b21e962c6b7b2d8fdf89c9c46ba919fc71"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "4b2b3bd4-d28f-44cc-96b3-4a2f64213109" ascii wide
		$typelibguid0up = "4B2B3BD4-D28F-44CC-96B3-4A2F64213109" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}