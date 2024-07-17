
rule SIGNATURE_BASE_HKTL_NET_NAME_Recon_AD : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "097de5cd-0cd4-59cc-a7b7-54cad8e6d230"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/outflanknl/Recon-AD"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_names.yar#L267-L280"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7bfafb2d3e85bb584bd02cb92457d22b07626f71d071c44a4aefbb5748045446"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "Recon-AD" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}