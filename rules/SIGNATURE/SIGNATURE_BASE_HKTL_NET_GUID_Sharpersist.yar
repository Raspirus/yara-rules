import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpersist : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "0c181186-7bb4-502b-8937-60cfd88ce689"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/fireeye/SharPersist"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2901-L2915"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "85a96c0fcbbc0ddb2fd0eab77c33976345120e575e5954e35bb4a61ff534b15a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "9d1b853e-58f1-4ba5-aefc-5c221ca30e48" ascii wide
		$typelibguid0up = "9D1B853E-58F1-4BA5-AEFC-5C221CA30E48" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}