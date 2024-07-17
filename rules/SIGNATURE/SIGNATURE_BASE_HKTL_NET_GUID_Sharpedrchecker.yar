rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpedrchecker : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "f7ff344e-f8ee-5c3a-bdd1-de3cae8e7dfb"
		date = "2020-12-18"
		modified = "2023-04-06"
		reference = "https://github.com/PwnDexter/SharpEDRChecker"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2565-L2579"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "9da3ff753db6358029f1fdcb100bf6173d142096557c170ddcb3ac9b8c80b310"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "bdfee233-3fed-42e5-aa64-492eb2ac7047" ascii wide
		$typelibguid0up = "BDFEE233-3FED-42E5-AA64-492EB2AC7047" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}