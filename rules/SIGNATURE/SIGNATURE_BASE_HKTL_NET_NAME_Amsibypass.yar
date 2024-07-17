
rule SIGNATURE_BASE_HKTL_NET_NAME_Amsibypass : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "26db14d8-1034-5bd1-a719-4756c832901d"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/0xB455/AmsiBypass"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_names.yar#L251-L265"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "8fa4ba512b34a898c4564a8eac254b6a786d195b"
		logic_hash = "e445c541a723ab05072ed38d6143d0a99c7db0ba6889b87fad147dc9a01be9d7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "AmsiBypass" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}