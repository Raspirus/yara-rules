import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpwitness : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "5e707da6-b2dd-511e-89ad-d19b93e8fca6"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/rasta-mouse/SharpWitness"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2869-L2883"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7339e77168c23cc218892db37fad0a6806b15d57a83b75b5da53c2f5e04b327d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "b9f6ec34-4ccc-4247-bcef-c1daab9b4469" ascii wide
		$typelibguid0up = "B9F6EC34-4CCC-4247-BCEF-C1DAAB9B4469" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}