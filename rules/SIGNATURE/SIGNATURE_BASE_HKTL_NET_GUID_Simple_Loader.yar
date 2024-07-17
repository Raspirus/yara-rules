import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Simple_Loader : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "4c26aaf9-187d-5990-b956-1bbf630411f0"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/cribdragg3r/Simple-Loader"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1456-L1470"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c94da47cdcf94f71d0909f1532108442e324e79e249646e5619865bdbd2d3c14"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "035ae711-c0e9-41da-a9a2-6523865e8694" ascii wide
		$typelibguid0up = "035AE711-C0E9-41DA-A9A2-6523865E8694" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}