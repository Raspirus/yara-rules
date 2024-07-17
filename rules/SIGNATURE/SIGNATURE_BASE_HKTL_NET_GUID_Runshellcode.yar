rule SIGNATURE_BASE_HKTL_NET_GUID_Runshellcode : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "249da967-68b0-59b1-b414-4eb4fe67b8f3"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/zerosum0x0/RunShellcode"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L170-L184"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "de9bb2689e10d8a4d4830f6fb5ac35f4433ece1fe61e0f04d72a125e85235a64"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "a3ec18a3-674c-4131-a7f5-acbed034b819" ascii wide
		$typelibguid0up = "A3EC18A3-674C-4131-A7F5-ACBED034B819" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}