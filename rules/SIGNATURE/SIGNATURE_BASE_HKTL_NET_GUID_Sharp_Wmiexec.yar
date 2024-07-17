rule SIGNATURE_BASE_HKTL_NET_GUID_Sharp_Wmiexec : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "ae08a5a2-06d5-55fe-803a-7f4696220904"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/checkymander/Sharp-WMIExec"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4007-L4021"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c5f515ac8db4cca0b29b6d27ad27fa1d4215de48d4827c083f755e88671b87e0"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "0a63b0a1-7d1a-4b84-81c3-bbbfe9913029" ascii wide
		$typelibguid0up = "0A63B0A1-7D1A-4B84-81C3-BBBFE9913029" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}