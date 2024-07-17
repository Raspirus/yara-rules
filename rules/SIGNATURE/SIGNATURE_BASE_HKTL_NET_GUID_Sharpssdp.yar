rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpssdp : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "8441e940-ab7c-5467-9db8-35f71bd57580"
		date = "2023-03-22"
		modified = "2023-04-06"
		reference = "https://github.com/rvrsh3ll/SharpSSDP"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L5262-L5276"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "0bb30d6b35db2b8144d284f25051f231ce6684f6a1213dc24ba2da0d5e4d4603"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "6e383de4-de89-4247-a41a-79db1dc03aaa" ascii wide
		$typelibguid0up = "6E383DE4-DE89-4247-A41A-79DB1DC03AAA" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}