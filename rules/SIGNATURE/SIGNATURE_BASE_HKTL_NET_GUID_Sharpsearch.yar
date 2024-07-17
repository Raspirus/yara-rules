import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpsearch : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "459d8a34-f311-5459-8257-e7aa519174b5"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/djhohnstein/SharpSearch"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3839-L3853"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b213a12913abb631d67bf53049241a7087e3f9cda01fa66bd6c51bb1bd03c41f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "98fee742-8410-4f20-8b2d-d7d789ab003d" ascii wide
		$typelibguid0up = "98FEE742-8410-4F20-8B2D-D7D789AB003D" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}