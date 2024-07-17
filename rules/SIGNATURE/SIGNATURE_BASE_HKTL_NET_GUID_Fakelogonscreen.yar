rule SIGNATURE_BASE_HKTL_NET_GUID_Fakelogonscreen : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "cc20290c-3f34-5e81-9337-c582f1ee7ade"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/bitsadmin/fakelogonscreen"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4048-L4062"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "4f7f2c075860994b29a211b3cb30fa75b7b6e3ac60a68bbaa9ecf7e4467b4ed0"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "d35a55bd-3189-498b-b72f-dc798172e505" ascii wide
		$typelibguid0up = "D35A55BD-3189-498B-B72F-DC798172E505" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}