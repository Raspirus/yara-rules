rule SIGNATURE_BASE_HKTL_NET_GUID_SHAPESHIFTER : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "8903c65a-624f-5e8d-a3f6-4572b56bd2f7"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/matterpreter/SHAPESHIFTER"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L744-L758"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "9c53ead8bc93f874b9fab11be0e281fa11f2c590a4c9e649d67eed84de79783d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "a3ddfcaa-66e7-44fd-ad48-9d80d1651228" ascii wide
		$typelibguid0up = "A3DDFCAA-66E7-44FD-AD48-9D80D1651228" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}