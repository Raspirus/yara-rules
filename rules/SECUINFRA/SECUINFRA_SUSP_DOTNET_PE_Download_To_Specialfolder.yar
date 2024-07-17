rule SECUINFRA_SUSP_DOTNET_PE_Download_To_Specialfolder : DOTNET DOWNLOAD FILE
{
	meta:
		description = "Detects a .NET Binary that downloads further payload and retrieves a special folder"
		author = "SECUINFRA Falcon Team"
		id = "106683bf-1d36-58ee-b5af-4723aa70fdad"
		date = "2022-02-27"
		modified = "2022-02-27"
		reference = "https://github.com/SIFalcon/Detection"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Filetypes/exe.yar#L45-L64"
		license_url = "N/A"
		logic_hash = "d44c89ab126f79596c8bf3f1327b37a2463faa4e3bb258f9a96d495ac40003f8"
		score = 65
		quality = 70
		tags = "DOTNET, DOWNLOAD, FILE"

	strings:
		$special_folder = "Environment.SpecialFolder" wide
		$webclient = "WebClient()" wide
		$download = ".DownloadFile(" wide

	condition:
		uint16(0)==0x5a4d and filesize <100KB and pe.imports("mscoree.dll") and $special_folder and $webclient and $download
}