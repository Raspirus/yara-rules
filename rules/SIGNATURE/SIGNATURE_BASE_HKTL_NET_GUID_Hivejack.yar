import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Hivejack : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "10567ef4-780f-5e93-9061-3214116d6bbb"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/Viralmaniar/HiveJack"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3356-L3370"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "22ca377cc1f1d634564084e92e976e21df0cf8bf864cb772a49f740a6a429a4e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "e12e62fe-bea3-4989-bf04-6f76028623e3" ascii wide
		$typelibguid0up = "E12E62FE-BEA3-4989-BF04-6F76028623E3" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}