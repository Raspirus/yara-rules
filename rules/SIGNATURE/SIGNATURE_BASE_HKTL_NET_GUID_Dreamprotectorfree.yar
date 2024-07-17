import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Dreamprotectorfree : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "9ebee989-3441-5a76-b243-08de978b541c"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/Paskowsky/DreamProtectorFree"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L908-L922"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "04c6daa23bbca852f83853e717c81622130beb3ac2551f8c3e23d2ec75aa0376"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "f7e8a902-2378-426a-bfa5-6b14c4b40aa3" ascii wide
		$typelibguid0up = "F7E8A902-2378-426A-BFA5-6B14C4B40AA3" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}