rule SIGNATURE_BASE_HKTL_NET_GUID_Gmsapasswordreader : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "dc74bfce-90a1-53bd-bfe4-cb7c9c75da53"
		date = "2023-12-06"
		modified = "2024-04-24"
		reference = "https://github.com/rvazarkar/GMSAPasswordReader"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L5536-L5548"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8db260b15b8b8158e5f66268b9086b456386af017e4351025ea27b9f994e5bf5"
		score = 75
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0 = "c8112750-972d-4efa-a75b-da9b8a4533c7" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}