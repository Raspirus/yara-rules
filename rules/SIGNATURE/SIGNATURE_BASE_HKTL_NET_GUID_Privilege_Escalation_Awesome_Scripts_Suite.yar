import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Privilege_Escalation_Awesome_Scripts_Suite : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "fa218dfa-4b56-5a62-b149-63394bd0b604"
		date = "2021-01-21"
		modified = "2023-04-06"
		reference = "https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4571-L4585"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a70cfe807cbba80e0bc79adcb7268b2c9b99c20c5f7454e2275712a1adbeb16c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "1928358e-a64b-493f-a741-ae8e3d029374" ascii wide
		$typelibguid0up = "1928358E-A64B-493F-A741-AE8E3D029374" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}