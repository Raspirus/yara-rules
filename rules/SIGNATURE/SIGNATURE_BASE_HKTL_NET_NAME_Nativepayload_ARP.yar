rule SIGNATURE_BASE_HKTL_NET_NAME_Nativepayload_ARP : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "9fac11f8-4e40-5cbc-a990-2ae48df20828"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/DamonMohammadbagher/NativePayload_ARP"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_names.yar#L567-L580"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e8cecfe09f1cb80eb693eb293dfb8c1bc3885a96dfa045b2391216c5f6f6f983"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "NativePayload_ARP" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}