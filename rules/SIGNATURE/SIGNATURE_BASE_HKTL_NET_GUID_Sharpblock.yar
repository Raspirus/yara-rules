import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpblock : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "b84538da-1b0e-50c7-abfa-e93d6de5a49b"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/CCob/SharpBlock"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L266-L280"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "4e2583de504884f421425f86fc4364e5bdde55946c19eebbcc64933e03357622"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "3cf25e04-27e4-4d19-945e-dadc37c81152" ascii wide
		$typelibguid0up = "3CF25E04-27E4-4D19-945E-DADC37C81152" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}