rule SIGNATURE_BASE_HKTL_NET_GUID_Evasor : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "457959ed-3e90-52c7-89f9-e1b17b35260e"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/cyberark/Evasor"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L760-L774"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "69bda55c5a1c8f432c582066eab5efb2aa443fbf0a73e7c4d16d7e987cf1db2e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "1c8849ef-ad09-4727-bf81-1f777bd1aef8" ascii wide
		$typelibguid0up = "1C8849EF-AD09-4727-BF81-1F777BD1AEF8" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}