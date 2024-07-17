rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpmove : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "e52392f9-614c-596e-8efd-aa0a2fa44e60"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/0xthirteen/SharpMove"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3585-L3599"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "4dd05b77d8cacb0dc208ee7bdde5358adfdf0bb04f52f1d6f12774effc547ca7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "8bf82bbe-909c-4777-a2fc-ea7c070ff43e" ascii wide
		$typelibguid0up = "8BF82BBE-909C-4777-A2FC-EA7C070FF43E" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}