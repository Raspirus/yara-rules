import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharphide : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "928e00c1-549a-58f5-9e7e-982a4319691a"
		date = "2021-01-21"
		modified = "2023-04-06"
		reference = "https://github.com/outflanknl/SharpHide"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4779-L4793"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "3efa5458dcdf447184b91f8fa075c46c82aea25d619c43eabccce4d85ff15f38"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "443d8cbf-899c-4c22-b4f6-b7ac202d4e37" ascii wide
		$typelibguid0up = "443D8CBF-899C-4C22-B4F6-B7AC202D4E37" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}