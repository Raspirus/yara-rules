
rule SECUINFRA_DROPPER_Asyncrat_VBS_February_2022_1 : FILE
{
	meta:
		description = "No description has been set in the source file - SecuInfra"
		author = "SECUINFRA Falcon Team"
		id = "80f84c2f-7af0-55c1-bc06-d605beae3e33"
		date = "2022-02-21"
		modified = "2022-02-21"
		reference = "https://bazaar.abuse.ch/sample/06cd1e75f05d55ac1ea77ef7bee38bb3b748110b79128dab4c300f1796a2b941/"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Dropper/asyncrat.yar#L2-L18"
		license_url = "N/A"
		logic_hash = "80c86b0cbb7382135bb9ae8c80ac42f499081fe1fe48fadf21f0e136bcc04358"
		score = 75
		quality = 70
		tags = "FILE"

	strings:
		$a1 = "http://3.145.46.6/"
		$b1 = "Const HIDDEN_WINDOW = 0"
		$b2 = "GetObject(\"winmgmts:\\\\"
		$c = "replace("

	condition:
		filesize <10KB and ($a1 or ( all of ($b*) and #c>10))
}