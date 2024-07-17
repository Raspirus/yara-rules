import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharprdp : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "d316ec0b-0313-52bb-923d-512fa08112f9"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/0xthirteen/SharpRDP"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3919-L3933"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c1a51c556c3416095764d3e053d82081409cdd672db05b8680a985ec52bd24b8"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "f1df1d0f-ff86-4106-97a8-f95aaf525c54" ascii wide
		$typelibguid0up = "F1DF1D0F-FF86-4106-97A8-F95AAF525C54" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}