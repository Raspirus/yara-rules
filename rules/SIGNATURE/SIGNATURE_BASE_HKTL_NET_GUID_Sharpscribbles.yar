import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpscribbles : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "47125b76-9388-5372-8810-d198f623367a"
		date = "2021-01-21"
		modified = "2023-04-06"
		reference = "https://github.com/V1V1/SharpScribbles"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4639-L4655"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7b592dc541b708e001f2576d9eb412ecc52879d514149e9f211f6357faff92fc"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "aa61a166-31ef-429d-a971-ca654cd18c3b" ascii wide
		$typelibguid0up = "AA61A166-31EF-429D-A971-CA654CD18C3B" ascii wide
		$typelibguid1lo = "0dc1b824-c6e7-4881-8788-35aecb34d227" ascii wide
		$typelibguid1up = "0DC1B824-C6E7-4881-8788-35AECB34D227" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}