import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Watson : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "6dc7bb08-0b34-50a0-8ae8-02d96d66a334"
		date = "2020-12-21"
		modified = "2023-04-06"
		reference = "https://github.com/rasta-mouse/Watson"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2717-L2731"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "cc7134a974b11b677e368f4f01ec534578bcd970282dc2c8b7f4852cb028514a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "49ad5f38-9e37-4967-9e84-fe19c7434ed7" ascii wide
		$typelibguid0up = "49AD5F38-9E37-4967-9E84-FE19C7434ED7" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}