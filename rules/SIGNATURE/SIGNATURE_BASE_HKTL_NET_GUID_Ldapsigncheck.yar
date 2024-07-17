import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Ldapsigncheck : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "a8b902f0-61a5-509e-8307-79bf557e5f61"
		date = "2023-03-15"
		modified = "2023-04-06"
		reference = "https://github.com/cube0x0/LdapSignCheck"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L5100-L5114"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c075fabcd39cecc2c5b5d706a1ac305bb75522b9d7f8c8cba11ca2d80da814a0"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "21f398a9-bc35-4bd2-b906-866f21409744" ascii wide
		$typelibguid0up = "21F398A9-BC35-4BD2-B906-866F21409744" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}