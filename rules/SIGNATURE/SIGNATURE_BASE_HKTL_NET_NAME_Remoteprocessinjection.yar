
rule SIGNATURE_BASE_HKTL_NET_NAME_Remoteprocessinjection : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "f1698cf2-211a-551a-8bc4-4faefcc6106f"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/Mr-Un1k0d3r/RemoteProcessInjection"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_names.yar#L747-L760"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "87d803c361462877f5ebba2a70f611c95b8684fe9f9f747ccf9643fc4e97d9df"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "RemoteProcessInjection" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}