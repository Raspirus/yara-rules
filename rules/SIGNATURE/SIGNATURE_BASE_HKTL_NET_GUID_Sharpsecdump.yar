import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpsecdump : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "492dfb79-541a-589d-ac69-468e9b2ab9db"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/G0ldenGunSec/SharpSecDump"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3855-L3869"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "645e2df929b88526daec94f5b828235899fe0c86822960777664f11106b8da8c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "e2fdd6cc-9886-456c-9021-ee2c47cf67b7" ascii wide
		$typelibguid0up = "E2FDD6CC-9886-456C-9021-EE2C47CF67B7" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}