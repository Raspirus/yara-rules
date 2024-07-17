rule HARFANGLAB_Samecoin_Campaign_Wiper : FILE
{
	meta:
		description = "Matches the wiper used in the SameCoin campaign"
		author = "HarfangLab"
		id = "695e9181-cc96-5212-b33c-4d55065b7b85"
		date = "2024-02-13"
		modified = "2024-04-05"
		reference = "TRR240201"
		source_url = "https://github.com/HarfangLab/iocs/blob/911b0f27d123986b25ad00cc0e7d94a52435cb15/TRR240201/trr240201_yara.yar#L23-L41"
		license_url = "N/A"
		hash = "e6d2f43622e3ecdce80939eec9fffb47e6eb7fc0b9aa036e9e4e07d7360f2b89"
		logic_hash = "ebe7c90398464ecf74ede17551c2ebc58b851ba6502092320934d1f5353581a2"
		score = 75
		quality = 80
		tags = "FILE"
		context = "file"

	strings:
		$code = { 68 57 04 00 00 50 E8 }
		$wl_1 = "C:\\Users\\Public\\Microsoft Connection Agent.jpg" ascii
		$wl_2 = "C:\\Users\\Public\\Video.mp4" ascii
		$wl_3 = "C:\\Users\\Public\\Microsoft System Agent.exe" ascii
		$wl_4 = "C:\\Users\\Public\\Microsoft System Manager.exe" ascii
		$wl_5 = "C:\\Users\\Public\\Windows Defender Agent.exe" ascii

	condition:
		uint16(0)==0x5A4D and filesize <200KB and $code and 3 of ($wl_*)
}