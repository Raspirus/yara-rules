import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpshell : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "5966be44-c010-5c63-9576-1aaf36397d6c"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/cobbr/SharpShell"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L538-L554"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "1a0d81f4bccde400d981da9cf769972fe1b8da44911c0805e6226f1db2ba0e84"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "bdba47c5-e823-4404-91d0-7f6561279525" ascii wide
		$typelibguid0up = "BDBA47C5-E823-4404-91D0-7F6561279525" ascii wide
		$typelibguid1lo = "b84548dc-d926-4b39-8293-fa0bdef34d49" ascii wide
		$typelibguid1up = "B84548DC-D926-4B39-8293-FA0BDEF34D49" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}