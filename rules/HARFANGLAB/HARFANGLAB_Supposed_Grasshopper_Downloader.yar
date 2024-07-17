rule HARFANGLAB_Supposed_Grasshopper_Downloader : FILE
{
	meta:
		description = "Detects the Nim downloader from the Supposed Grasshopper campaign."
		author = "HarfangLab"
		id = "e53656b5-a1be-53f0-a4d4-908f24e08bd6"
		date = "2024-06-20"
		modified = "2024-06-28"
		reference = "TRR240601"
		source_url = "https://github.com/HarfangLab/iocs/blob/911b0f27d123986b25ad00cc0e7d94a52435cb15/TRR240601/trr240601_yara.yar#L1-L16"
		license_url = "N/A"
		logic_hash = "93509319ab8028b0215fcfb81d1ff5d3d810922999f1dd8359b706a965221b2f"
		score = 75
		quality = 80
		tags = "FILE"
		context = "file,memory"

	strings:
		$pdb_path = "C:\\Users\\or\\Desktop\\nim-" ascii
		$code = "helo.nim" ascii
		$function_1 = "DownloadExecute" ascii fullword
		$function_2 = "toByteSeq" ascii fullword

	condition:
		uint16(0)==0x5a4d and all of them
}