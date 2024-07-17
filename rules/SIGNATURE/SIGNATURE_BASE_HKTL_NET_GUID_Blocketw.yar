rule SIGNATURE_BASE_HKTL_NET_GUID_Blocketw : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "c2b72fef-6549-5b53-8ccf-232e8d152e96"
		date = "2020-12-29"
		modified = "2023-04-06"
		reference = "https://github.com/Soledge/BlockEtw"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4230-L4244"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "4670091775772f66e82dd7c78ac8f307d301ce849424dabcaf495c46cd737d7f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "daedf7b3-8262-4892-adc4-425dd5f85bca" ascii wide
		$typelibguid0up = "DAEDF7B3-8262-4892-ADC4-425DD5F85BCA" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}