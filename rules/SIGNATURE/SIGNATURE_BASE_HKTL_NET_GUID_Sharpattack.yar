rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpattack : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "1eb911ab-3fb9-54b7-8afb-66328f30d563"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/jaredhaight/SharpAttack"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4082-L4096"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "2103b98f188d74c340d6ca71590be32c04cadba893882aebf4e22f5046ae4bc9"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "5f0ceca3-5997-406c-adf5-6c7fbb6cba17" ascii wide
		$typelibguid0up = "5F0CECA3-5997-406C-ADF5-6C7FBB6CBA17" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}