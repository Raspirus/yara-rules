import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpallowedtoact : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "13b7f5e0-4d34-533d-a182-b3fe7c93ca43"
		date = "2021-01-21"
		modified = "2023-04-06"
		reference = "https://github.com/pkb1s/SharpAllowedToAct"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4523-L4537"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "872f4d70f7cefff8c1fadbe61d858c898a259559889ca4951f5368589d28169d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "dac5448a-4ad1-490a-846a-18e4e3e0cf9a" ascii wide
		$typelibguid0up = "DAC5448A-4AD1-490A-846A-18E4E3E0CF9A" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}