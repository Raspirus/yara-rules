
rule SIGNATURE_BASE_HKTL_NET_NAME_Sharpbuster : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "d30c8ee5-88b9-53b5-b209-51f6f3b988cf"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/passthehashbrowns/SharpBuster"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_names.yar#L236-L249"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "cdc19e03f75f34e6349937c0bff313298fc9310f361eec7af022c450d083ad96"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "SharpBuster" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}