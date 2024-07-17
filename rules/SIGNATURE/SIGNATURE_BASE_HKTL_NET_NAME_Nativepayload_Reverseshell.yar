rule SIGNATURE_BASE_HKTL_NET_NAME_Nativepayload_Reverseshell : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "eec77c09-02db-5d74-8526-e201d2fe6fc8"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/DamonMohammadbagher/NativePayload_ReverseShell"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_names.yar#L642-L655"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "79ebde95674d76e58938b06a97cb6c65e6ac0606398fc9c30d90e517bbdd62a8"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "NativePayload_ReverseShell" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}