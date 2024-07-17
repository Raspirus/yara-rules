rule SIGNATURE_BASE_HKTL_NET_GUID_Azurecli_Extractor : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "f595545a-a7a6-577c-b3f4-febf7bf1b6c3"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/0x09AL/AzureCLI-Extractor"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L590-L604"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "5ea4dd540a39ac1160da15434b19036a99da69ea999ca0b0f5193fe32a263dca"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "a73cad74-f8d6-43e6-9a4c-b87832cdeace" ascii wide
		$typelibguid0up = "A73CAD74-F8D6-43E6-9A4C-B87832CDEACE" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}