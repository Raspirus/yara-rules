rule SECUINFRA_SUSP_DOTNET_PE_List_AV : DOTNET AV FILE
{
	meta:
		description = "Detecs .NET Binary that lists installed AVs"
		author = "SECUINFRA Falcon Team"
		id = "0f27567a-ab41-5d17-a1d8-a59c9602eb35"
		date = "2022-02-27"
		modified = "2022-02-27"
		reference = "https://github.com/SIFalcon/Detection"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Filetypes/exe.yar#L66-L82"
		license_url = "N/A"
		logic_hash = "b82e6ed5740cab26eb3848717204190d61663e7e42ff42536386b00181a15ebb"
		score = 65
		quality = 70
		tags = "DOTNET, AV, FILE"

	strings:
		$mgt_obj_searcher = "\\root\\SecurityCenter2" wide
		$query = "Select * from AntivirusProduct" wide

	condition:
		uint16(0)==0x5a4d and filesize <200KB and pe.imports("mscoree.dll") and $mgt_obj_searcher and $query
}