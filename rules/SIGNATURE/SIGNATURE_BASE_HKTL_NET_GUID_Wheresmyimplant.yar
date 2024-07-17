rule SIGNATURE_BASE_HKTL_NET_GUID_Wheresmyimplant : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "c99523ce-e2c0-5a21-89d1-70c0dd970731"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/0xbadjuju/WheresMyImplant"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3230-L3244"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "0bc82dfd6e07f6ff8a9cb7b6331f3f600db30ee053592422d1eddaff3c46cfdf"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "cca59e4e-ce4d-40fc-965f-34560330c7e6" ascii wide
		$typelibguid0up = "CCA59E4E-CE4D-40FC-965F-34560330C7E6" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}