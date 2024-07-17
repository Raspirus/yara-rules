rule SIGNATURE_BASE_HKTL_NET_GUID_Reverseshell : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "876932d5-a65d-5230-9cb8-24038ad8af0d"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/chango77747/ReverseShell"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L462-L478"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b736919d47877bcca21ba0fb136fe2ed39b645f6b1e9e9b5f0f2fc4758814174"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "980109e4-c988-47f9-b2b3-88d63fababdc" ascii wide
		$typelibguid0up = "980109E4-C988-47F9-B2B3-88D63FABABDC" ascii wide
		$typelibguid1lo = "8abe8da1-457e-4933-a40d-0958c8925985" ascii wide
		$typelibguid1up = "8ABE8DA1-457E-4933-A40D-0958C8925985" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}