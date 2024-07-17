rule SIGNATURE_BASE_HKTL_NET_GUID_Bantam : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "0ed3f5e5-d954-51e2-b7fb-4c25ca3d9f10"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/gellin/bantam"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L974-L988"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a1d0749746dc3a109b592165616f829d01cfb4be8e16137548be8a85c40d6eb7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "14c79bda-2ce6-424d-bd49-4f8d68630b7b" ascii wide
		$typelibguid0up = "14C79BDA-2CE6-424D-BD49-4F8D68630B7B" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}