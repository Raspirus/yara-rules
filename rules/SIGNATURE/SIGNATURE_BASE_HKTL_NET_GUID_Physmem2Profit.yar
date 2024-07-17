import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Physmem2Profit : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "75a27970-c469-53da-b0c3-b3d0faea0b6f"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/FSecureLABS/physmem2profit"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L234-L248"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "60385891640e18699e17d1282b4af03ecd0ea3ceaf153bf54560242097595b2f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "814708c9-2320-42d2-a45f-31e42da06a94" ascii wide
		$typelibguid0up = "814708C9-2320-42D2-A45F-31E42DA06A94" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}