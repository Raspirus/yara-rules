import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Limelogger : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "0798f01b-76b7-5c4d-9ddb-5e377b86f8b9"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/NYAN-x-CAT/LimeLogger"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L298-L312"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "1afc5f5f236d66374f5c53f770e8284867632b0373de00283175ed1d424bfa4b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "068d14ef-f0a1-4f9d-8e27-58b4317830c6" ascii wide
		$typelibguid0up = "068D14EF-F0A1-4F9D-8E27-58B4317830C6" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}