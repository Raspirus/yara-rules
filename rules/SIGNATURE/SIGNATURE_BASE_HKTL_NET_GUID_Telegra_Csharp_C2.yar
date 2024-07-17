rule SIGNATURE_BASE_HKTL_NET_GUID_Telegra_Csharp_C2 : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "495a5f3e-cf05-5a66-b01c-8176ded88768"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/sf197/Telegra_Csharp_C2"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1376-L1390"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b931009110366712cc9d69a7cb7feaa7a02f7baa93bc3c3fbb76c4132554b10e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "1d79fabc-2ba2-4604-a4b6-045027340c85" ascii wide
		$typelibguid0up = "1D79FABC-2BA2-4604-A4B6-045027340C85" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}