import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Decryptautologon : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "3ef58da9-16c1-54cf-9d06-a05680548cf5"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/securesean/DecryptAutoLogon"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3372-L3386"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "2d8d05f568528616da30f0f35c3baf7ba762e33319a7d7975ddb23e42944884f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "015a37fc-53d0-499b-bffe-ab88c5086040" ascii wide
		$typelibguid0up = "015A37FC-53D0-499B-BFFE-AB88C5086040" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}