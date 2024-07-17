import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Registrystrikesback : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "1577ed24-0e17-54f9-bc29-bb209acf9645"
		date = "2021-01-21"
		modified = "2023-04-06"
		reference = "https://github.com/mdsecactivebreach/RegistryStrikesBack"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4859-L4873"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "fa228e65f6bada1811c83528af8119b5336ebbc2381d5edef35c749ddff02487"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "90ebd469-d780-4431-9bd8-014b00057665" ascii wide
		$typelibguid0up = "90EBD469-D780-4431-9BD8-014B00057665" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}