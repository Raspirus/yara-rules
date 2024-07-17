
rule HARFANGLAB_Samecoin_Campaign_Loader : FILE
{
	meta:
		description = "Matches the loader used in the SameCoin campaign"
		author = "HarfangLab"
		id = "ab4d59f6-300d-5cdf-b91f-87f8cc1f0eac"
		date = "2024-02-13"
		modified = "2024-04-05"
		reference = "TRR240201"
		source_url = "https://github.com/HarfangLab/iocs/blob/911b0f27d123986b25ad00cc0e7d94a52435cb15/TRR240201/trr240201_yara.yar#L1-L21"
		license_url = "N/A"
		hash = "cff976d15ba6c14c501150c63b69e6c06971c07f8fa048a9974ecf68ab88a5b6"
		logic_hash = "7df04ab208d2caa5a137b1c3481ef734df54bbe8330979f524b16e9ba8cf48d5"
		score = 75
		quality = 80
		tags = "FILE"
		context = "file"

	strings:
		$hebrew_layout = "0000040d" fullword ascii
		$runas = "runas" fullword ascii
		$jpg_magic = { FF D8 FF E0 00 10 4A 46 49 46 00 01 }
		$wl_1 = "C:\\Users\\Public\\Microsoft Connection Agent.jpg" ascii
		$wl_2 = "C:\\Users\\Public\\Video.mp4" ascii
		$wl_3 = "C:\\Users\\Public\\Microsoft System Agent.exe" ascii
		$wl_4 = "C:\\Users\\Public\\Microsoft System Manager.exe" ascii
		$wl_5 = "C:\\Users\\Public\\Windows Defender Agent.exe"

	condition:
		uint16(0)==0x5A4D and filesize >5MB and filesize <7MB and $hebrew_layout and $runas and $jpg_magic and 3 of ($wl_*)
}