rule SIGNATURE_BASE_HKTL_NET_GUID_Scout : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "cd24cca7-3bc0-5e7a-9817-dc3b26ec8358"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/jaredhaight/scout"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2933-L2947"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8bd735b4c4c3af209475b633c00fc8f01b2e9a3a5e5e29557a578d87e7bd0836"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "d9c76e82-b848-47d4-8f22-99bf22a8ee11" ascii wide
		$typelibguid0up = "D9C76E82-B848-47D4-8F22-99BF22A8EE11" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}