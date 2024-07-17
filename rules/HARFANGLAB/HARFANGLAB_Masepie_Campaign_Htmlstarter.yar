rule HARFANGLAB_Masepie_Campaign_Htmlstarter : FILE
{
	meta:
		description = "Detect Malicious Web page HTML file from CERT-UA#8399"
		author = "HarfangLab"
		id = "0cca485c-7941-5760-8c24-d993dcbf376d"
		date = "2024-01-24"
		modified = "2024-01-31"
		reference = "TRR240101;https://cert.gov.ua/article/6276894"
		source_url = "https://github.com/HarfangLab/iocs/blob/911b0f27d123986b25ad00cc0e7d94a52435cb15/TRR240101/trr240101_yara.yar#L1-L16"
		license_url = "N/A"
		hash = "628bc9f4aa71a015ec415d5d7d8cb168359886a231e17ecac2e5664760ee8eba"
		logic_hash = "d131372c6ad01ae77e5630bae0c0a04ce311718eb1bcf423e6575f3b0ecdba5d"
		score = 75
		quality = 80
		tags = "FILE"
		context = "file"

	strings:
		$s1 = "<link rel=\"stylesheet\" href=\"a.css\">" ascii wide fullword
		$s2 = "src=\".\\Capture" ascii wide

	condition:
		filesize >600 and filesize <5KB and ( all of them )
}