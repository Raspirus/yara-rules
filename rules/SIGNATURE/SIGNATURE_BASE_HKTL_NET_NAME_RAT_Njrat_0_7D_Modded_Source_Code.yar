rule SIGNATURE_BASE_HKTL_NET_NAME_RAT_Njrat_0_7D_Modded_Source_Code : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "2b7d1f75-0164-561e-8199-32c601cbca98"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/AliBawazeEer/RAT-NjRat-0.7d-modded-source-code"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_names.yar#L507-L520"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f437195348452242adc8b55d6d517a17764c53188fa2de5cd15848fd23827381"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "RAT-NjRat-0.7d-modded-source-code" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}