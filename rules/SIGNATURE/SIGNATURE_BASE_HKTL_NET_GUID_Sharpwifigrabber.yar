import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpwifigrabber : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "1a457672-743c-56f0-a4d7-6c25f9ce2345"
		date = "2020-12-29"
		modified = "2023-04-06"
		reference = "https://github.com/r3nhat/SharpWifiGrabber"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4246-L4260"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "1924847602c4075779697f8b74dee48738f2a4e7852b2431c128e677f6c04407"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "c0997698-2b73-4982-b25b-d0578d1323c2" ascii wide
		$typelibguid0up = "C0997698-2B73-4982-B25B-D0578D1323C2" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}