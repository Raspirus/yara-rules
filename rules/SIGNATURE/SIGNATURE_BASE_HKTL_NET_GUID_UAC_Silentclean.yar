rule SIGNATURE_BASE_HKTL_NET_GUID_UAC_Silentclean : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "2dde9632-10c5-5c91-8bd9-2fb80d6f0c49"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/EncodeGroup/UAC-SilentClean"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1104-L1118"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "2e624d84a6d47c99b28ef41918f1d88cb219a90d35691d0cce8fe10a0a237650"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "948152a4-a4a1-4260-a224-204255bfee72" ascii wide
		$typelibguid0up = "948152A4-A4A1-4260-A224-204255BFEE72" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}