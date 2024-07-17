import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Stealth_Kid_RAT : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "f26e040a-dcc7-518f-89f2-3333f83fa14a"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/ctsecurity/Stealth-Kid-RAT"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1200-L1216"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "0c251c306f416d7a3192d7a11d87b99ab62e2d32453ddecb75a3c517f24a0342"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "bf43cd33-c259-4711-8a0e-1a5c6c13811d" ascii wide
		$typelibguid0up = "BF43CD33-C259-4711-8A0E-1A5C6C13811D" ascii wide
		$typelibguid1lo = "e5b9df9b-a9e4-4754-8731-efc4e2667d88" ascii wide
		$typelibguid1up = "E5B9DF9B-A9E4-4754-8731-EFC4E2667D88" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}