rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpshooter : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "a59e6fe9-dbaf-5830-8cf1-485ff4dd939a"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/mdsecactivebreach/SharpShooter"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3015-L3029"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8a8510a680205c09321b8d1a960f1b8026883aede5224e8fe541727a434312b4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "56598f1c-6d88-4994-a392-af337abe5777" ascii wide
		$typelibguid0up = "56598F1C-6D88-4994-A392-AF337ABE5777" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}