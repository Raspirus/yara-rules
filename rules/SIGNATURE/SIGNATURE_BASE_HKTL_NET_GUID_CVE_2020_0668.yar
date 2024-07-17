import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_CVE_2020_0668 : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "54c87578-f0f1-5108-a736-b6acd9624d29"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/RedCursorSecurityConsulting/CVE-2020-0668"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2809-L2823"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b72a5dff34f9674545acccad556204ed65dfdd587aa6a4d1fe542afd91e5a8d5"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "1b4c5ec1-2845-40fd-a173-62c450f12ea5" ascii wide
		$typelibguid0up = "1B4C5EC1-2845-40FD-A173-62C450F12EA5" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}