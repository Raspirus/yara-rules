rule SIGNATURE_BASE_HKTL_NET_GUID_Filesearcher : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "1b5f1f68-f87b-5e60-94a4-e2556b4e6c5d"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/NVISO-BE/FileSearcher"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3887-L3901"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "71492c6d4c1104cf47484556dc8ed1099348043102a4b7a9b1ffd180422078af"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "2c879479-5027-4ce9-aaac-084db0e6d630" ascii wide
		$typelibguid0up = "2C879479-5027-4CE9-AAAC-084DB0E6D630" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}