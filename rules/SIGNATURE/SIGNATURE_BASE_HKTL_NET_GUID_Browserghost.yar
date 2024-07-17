rule SIGNATURE_BASE_HKTL_NET_GUID_Browserghost : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "adcc5d12-c393-5708-ae0b-a85f2187c881"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/QAX-A-Team/BrowserGhost"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1949-L1965"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "1f9bdf4881a71c429cf20e7a635f054a4a340f335767cb22ecc8024bcc57e53b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "2133c634-4139-466e-8983-9a23ec99e01b" ascii wide
		$typelibguid0up = "2133C634-4139-466E-8983-9A23EC99E01B" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them and not pe.is_dll()
}