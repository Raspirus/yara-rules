rule SIGNATURE_BASE_HKTL_NET_GUID_Gray_Keylogger_2 : FILE
{
	meta:
		description = "Detects VB.NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "40ab8103-9151-5a5c-8b70-ab3bfd3896f9"
		date = "2020-12-30"
		modified = "2023-04-06"
		reference = "https://github.com/graysuit/gray-keylogger-2"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4333-L4349"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "eb7cbfcc7d57298d3ce325596834e94f3594bafb0273e9f81715114b21af6371"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "e94ca3ff-c0e5-4d1a-ad5e-f6ebbe365067" ascii wide
		$typelibguid0up = "E94CA3FF-C0E5-4D1A-AD5E-F6EBBE365067" ascii wide
		$typelibguid1lo = "1ed07564-b411-4626-88e5-e1cd8ecd860a" ascii wide
		$typelibguid1up = "1ED07564-B411-4626-88E5-E1CD8ECD860A" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}