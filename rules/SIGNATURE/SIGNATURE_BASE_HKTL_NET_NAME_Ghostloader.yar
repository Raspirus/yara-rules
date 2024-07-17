rule SIGNATURE_BASE_HKTL_NET_NAME_Ghostloader : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "d8d88f3f-f250-55ff-88a6-4623e12ef89d"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/TheWover/GhostLoader"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_names.yar#L167-L180"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "91527b4b35f2bb1aeee236647c5169c67f2b9cfb867f2b6d486bd8d8b7455d4b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "GhostLoader" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}