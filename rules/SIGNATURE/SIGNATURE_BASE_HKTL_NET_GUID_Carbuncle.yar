rule SIGNATURE_BASE_HKTL_NET_GUID_Carbuncle : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "4a87882e-570b-5b40-a8e3-47ebac01d257"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/checkymander/Carbuncle"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1408-L1422"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "3a5bd58ac42ed3a428d6f20f1956b5abe5dfd958e9768fb0e3916ee2672d9c55"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "3f239b73-88ae-413b-b8c8-c01a35a0d92e" ascii wide
		$typelibguid0up = "3F239B73-88AE-413B-B8C8-C01A35A0D92E" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}