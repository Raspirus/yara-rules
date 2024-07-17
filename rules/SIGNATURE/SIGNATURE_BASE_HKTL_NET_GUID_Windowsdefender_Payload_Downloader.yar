import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Windowsdefender_Payload_Downloader : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "6e494a91-c05e-5a2e-8aa9-77600f3bdd47"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/notkohlrexo/WindowsDefender-Payload-Downloader"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1552-L1566"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e4f0a7db1ff7dda5f66cb466cf70e717a9050541dd6a79acd9c8f5723267f5a4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "2f8b4d26-7620-4e11-b296-bc46eba3adfc" ascii wide
		$typelibguid0up = "2F8B4D26-7620-4E11-B296-BC46EBA3ADFC" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}