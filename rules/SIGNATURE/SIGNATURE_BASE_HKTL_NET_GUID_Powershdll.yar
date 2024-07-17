import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Powershdll : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "3f582a47-078e-525f-9d02-4ee7a455a3b2"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/p3nt4/PowerShdll"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L842-L856"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b000c10d55d7d8902c036306dd51a5f3d32b83e88c081f337140e448c2cd836e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "36ebf9aa-2f37-4f1d-a2f1-f2a45deeaf21" ascii wide
		$typelibguid0up = "36EBF9AA-2F37-4F1D-A2F1-F2A45DEEAF21" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}