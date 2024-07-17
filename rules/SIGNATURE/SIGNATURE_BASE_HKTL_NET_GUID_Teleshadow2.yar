import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Teleshadow2 : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "5b22f2c4-0bd1-5a5a-8867-8fbc773d2b44"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/ParsingTeam/TeleShadow2"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3049-L3065"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "effe10487be132548eb56eb5bfc97f394669a153c9a885e3461e5f9e94bf66f8"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "42c5c356-39cf-4c07-96df-ebb0ccf78ca4" ascii wide
		$typelibguid0up = "42C5C356-39CF-4C07-96DF-EBB0CCF78CA4" ascii wide
		$typelibguid1lo = "0242b5b1-4d26-413e-8c8c-13b4ed30d510" ascii wide
		$typelibguid1up = "0242B5B1-4D26-413E-8C8C-13B4ED30D510" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}