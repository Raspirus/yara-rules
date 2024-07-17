rule SECUINFRA_SUSP_Netsh_Firewall_Command : PE FILE
{
	meta:
		description = "No description has been set in the source file - SecuInfra"
		author = "SECUINFRA Falcon Team"
		id = "c62cbe3f-9585-56c0-bb09-83a36437abda"
		date = "2022-02-27"
		modified = "2022-02-27"
		reference = "https://github.com/SIFalcon/Detection"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Filetypes/exe.yar#L84-L97"
		license_url = "N/A"
		logic_hash = "7d19b433785684ce1d2b008b3fdd36b22c5c82bfec476c787dfa025080b6178d"
		score = 65
		quality = 70
		tags = "PE, FILE"

	strings:
		$netsh_delete = "netsh firewall delete" wide
		$netsh_add = "netsh firewall add" wide

	condition:
		uint16(0)==0x5a4d and filesize <100KB and ($netsh_delete or $netsh_add)
}