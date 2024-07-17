rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpchromium : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "5364956a-e199-556a-8055-0e7b9a7b14c8"
		date = "2023-03-22"
		modified = "2023-04-06"
		reference = "https://github.com/djhohnstein/SharpChromium"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L5368-L5382"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "00324bac8e8d9c335a359c2241e810d2e345ee6fb10a63b1bc05f33a7816c80d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "2133c634-4139-466e-8983-9a23ec99e01b" ascii wide
		$typelibguid0up = "2133C634-4139-466E-8983-9A23EC99E01B" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}