import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Trufflesnout : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "8135d39e-6a9e-567d-840f-8d8c6338cce1"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/dsnezhkov/TruffleSnout"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1847-L1861"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "5c3a69776d1c1f2503b85e410eef83067e178c22e08dcefdecbe73040bf1d737"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "33842d77-bce3-4ee8-9ee2-9769898bb429" ascii wide
		$typelibguid0up = "33842D77-BCE3-4EE8-9EE2-9769898BB429" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}