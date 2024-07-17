private rule AVASTTI_ELF_PRIVATE
{
	meta:
		description = "No description has been set in the source file - AvastTI"
		author = "Avast Threat Intel Team"
		id = "38aa7852-e7ea-5b90-a5f6-0862ad19a051"
		date = "2022-10-05"
		modified = "2022-10-05"
		reference = "https://github.com/avast/ioc"
		source_url = "https://github.com/avast/ioc/blob/19245ea6066a04f15e0859899546f1378ef578cb/Manjusaka/Manjusaka.yar#L1-L7"
		license_url = "N/A"
		logic_hash = "eb05e5d53bb8dea91467a76a164542894cdb1355cf3909f56818e27c589344ec"
		score = 75
		quality = 90
		tags = ""

	strings:
		$h01 = { 7F 45 4C 46 (01|02) (01|02) 01 }

	condition:
		$h01 at 0
}