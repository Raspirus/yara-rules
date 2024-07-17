import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Uglyexe : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "5833e6c5-f078-5eb5-9519-76710d7da0e1"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/fashionproof/UglyEXe"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1152-L1166"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7f3e5ef8fc7d6994c1ebab8fc35624691d8f200acf6068b0948fd818f8ad2223"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "233de44b-4ec1-475d-a7d6-16da48d6fc8d" ascii wide
		$typelibguid0up = "233DE44B-4EC1-475D-A7D6-16DA48D6FC8D" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}