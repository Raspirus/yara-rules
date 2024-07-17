import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpcradle : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "e2123a73-2609-559d-a122-923ebf8fd668"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/anthemtotheego/SharpCradle"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1218-L1232"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a56c456a7c4f61b65f603bc2c8449668a90e36f8b240bca8ea474d82e8174c78"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "f70d2b71-4aae-4b24-9dae-55bc819c78bb" ascii wide
		$typelibguid0up = "F70D2B71-4AAE-4B24-9DAE-55BC819C78BB" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}