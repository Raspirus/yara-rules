
rule SIGNATURE_BASE_HKTL_NET_NAME_Graykeylogger : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "c63875b6-1701-5594-927e-833c25dc5d98"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/DarkSecDevelopers/GrayKeylogger"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_names.yar#L432-L445"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b8e12c5ddf0d50d0b3681594c8bc3410a24dab00035a5959e20d20045dacbbbd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "GrayKeylogger" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}