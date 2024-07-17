rule SIGNATURE_BASE_HKTL_NET_GUID_P2P : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid (p2p Remote Desktop is dual use but 100% flagged as malicious on VT)"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "e7b2b4bd-f1e1-5062-9b36-5df44ae374ea"
		date = "2023-03-19"
		modified = "2023-04-06"
		reference = "https://github.com/miroslavpejic85/p2p"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L5198-L5212"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "fcdeb2f481232ba0d13642b3003a94435c4de4e90c342c0db7707a6751a66834"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "33456e72-f8e8-4384-88c4-700867df12e2" ascii wide
		$typelibguid0up = "33456E72-F8E8-4384-88C4-700867DF12E2" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}