import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_CVE_2019_1253 : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "3e18b533-1b85-5eaf-bb3d-aa5b90fd2e28"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/padovah4ck/CVE-2019-1253"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2917-L2931"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "964b3c21297295833a702160fc292dcbb06573e5341b81dfc05b641246c4b019"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "584964c1-f983-498d-8370-23e27fdd0399" ascii wide
		$typelibguid0up = "584964C1-F983-498D-8370-23E27FDD0399" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}