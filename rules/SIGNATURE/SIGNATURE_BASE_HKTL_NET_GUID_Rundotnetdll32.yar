rule SIGNATURE_BASE_HKTL_NET_GUID_Rundotnetdll32 : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "266c8add-d2ca-5e46-8594-5d190447d133"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/0xbadjuju/rundotnetdll32"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3280-L3294"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8d20de93f5e9f0fce189130862153e533a79038d4fdaadb3d4216b6bd294ae05"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "a766db28-94b6-4ed1-aef9-5200bbdd8ca7" ascii wide
		$typelibguid0up = "A766DB28-94B6-4ED1-AEF9-5200BBDD8CA7" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}