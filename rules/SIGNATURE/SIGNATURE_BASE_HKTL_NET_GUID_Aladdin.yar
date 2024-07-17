rule SIGNATURE_BASE_HKTL_NET_GUID_Aladdin : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "3f0a954c-f3b3-5e5d-a71d-11f60b026a48"
		date = "2023-03-13"
		modified = "2023-04-06"
		reference = "https://github.com/nettitude/Aladdin"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L5064-L5082"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ed23700de0e8d6527f64714b8c2e3a43c4a0798d710b67d6602b5d4ae276cbbd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "b2b3adb0-1669-4b94-86cb-6dd682ddbea3" ascii wide
		$typelibguid0up = "B2B3ADB0-1669-4B94-86CB-6DD682DDBEA3" ascii wide
		$typelibguid1lo = "c47e4d64-cc7f-490e-8f09-055e009f33ba" ascii wide
		$typelibguid1up = "C47E4D64-CC7F-490E-8F09-055E009F33BA" ascii wide
		$typelibguid2lo = "32a91b0f-30cd-4c75-be79-ccbd6345de99" ascii wide
		$typelibguid2up = "32A91B0F-30CD-4C75-BE79-CCBD6345DE99" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}