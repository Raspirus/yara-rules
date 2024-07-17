import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Mass_RAT : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "90b742da-6fd7-5c72-96cf-7a37a3e5d808"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/NYAN-x-CAT/Mass-RAT"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2157-L2175"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "540620ade0225df3fa207052c3904584672eb5bdccaa523e28a1a2aced604ef9"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "6c43a753-9565-48b2-a372-4210bb1e0d75" ascii wide
		$typelibguid0up = "6C43A753-9565-48B2-A372-4210BB1E0D75" ascii wide
		$typelibguid1lo = "92ba2a7e-c198-4d43-929e-1cfe54b64d95" ascii wide
		$typelibguid1up = "92BA2A7E-C198-4D43-929E-1CFE54B64D95" ascii wide
		$typelibguid2lo = "4cb9bbee-fb92-44fa-a427-b7245befc2f3" ascii wide
		$typelibguid2up = "4CB9BBEE-FB92-44FA-A427-B7245BEFC2F3" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}