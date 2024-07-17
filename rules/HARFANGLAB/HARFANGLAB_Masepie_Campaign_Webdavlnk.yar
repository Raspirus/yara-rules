rule HARFANGLAB_Masepie_Campaign_Webdavlnk : FILE
{
	meta:
		description = "Detect Malicious LNK from CERT-UA#8399"
		author = "HarfangLab"
		id = "de7fd592-e733-52d0-af9b-55adf37eaf74"
		date = "2024-01-24"
		modified = "2024-01-31"
		reference = "TRR240101;https://cert.gov.ua/article/6276894"
		source_url = "https://github.com/HarfangLab/iocs/blob/911b0f27d123986b25ad00cc0e7d94a52435cb15/TRR240101/trr240101_yara.yar#L18-L40"
		license_url = "N/A"
		hash = "19d0c55ac466e4188c4370e204808ca0bc02bba480ec641da8190cb8aee92bdc"
		logic_hash = "26075e47b54404c55f4ca5eb757efa2b1711d919de0ffbfbdf6935e2e4dd3f3d"
		score = 75
		quality = 80
		tags = "FILE"
		context = "file"

	strings:
		$a1 = "[system.Diagnostics.Process]::Start('msedge','http" wide nocase fullword
		$a2 = "\\Microsoft\\Edge\\Application\\msedge.exe" wide nocase fullword
		$a3 = "powershell.exe" ascii wide fullword
		$s1 = "win-j5ggokh35ap" ascii fullword
		$s2 = "desktop-q0f4sik" ascii fullword

	condition:
		filesize >1200 and filesize <5KB and ( uint16be(0)==0x4c00) and (( all of ($a*)) or ( any of ($s*)))
}