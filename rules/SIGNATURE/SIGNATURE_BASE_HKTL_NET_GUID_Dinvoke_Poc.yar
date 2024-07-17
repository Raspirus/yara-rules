rule SIGNATURE_BASE_HKTL_NET_GUID_Dinvoke_Poc : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "f3b0ef47-a92c-5c5d-a9e2-09579fcb438e"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/dtrizna/DInvoke_PoC"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L446-L460"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c72125f272d18801c36a4f5f8c877ae5ecf3a81bd9e58113ce79f2311c455c65"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "5a869ab2-291a-49e6-a1b7-0d0f051bef0e" ascii wide
		$typelibguid0up = "5A869AB2-291A-49E6-A1B7-0D0F051BEF0E" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}