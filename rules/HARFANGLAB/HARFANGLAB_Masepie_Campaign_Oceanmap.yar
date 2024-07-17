
rule HARFANGLAB_Masepie_Campaign_Oceanmap : FILE
{
	meta:
		description = "Detect OCEANMAP from CERT-UA#8399"
		author = "HarfangLab"
		id = "7dcbce01-ab91-56ae-8789-e2e25ba1bf8c"
		date = "2024-01-24"
		modified = "2024-01-31"
		reference = "TRR240101;https://cert.gov.ua/article/6276894"
		source_url = "https://github.com/HarfangLab/iocs/blob/911b0f27d123986b25ad00cc0e7d94a52435cb15/TRR240101/trr240101_yara.yar#L64-L98"
		license_url = "N/A"
		hash = "24fd571600dcc00bf2bb8577c7e4fd67275f7d19d852b909395bebcbb1274e04"
		logic_hash = "5fe244025f49358b4285e1272489378a46363ae915881dece26691d971aa93f3"
		score = 75
		quality = 78
		tags = "FILE"
		context = "file"

	strings:
		$dotNet = ".NETFramework,Version" ascii fullword
		$a1 = "$ SELECT INBOX.Drafts" wide fullword
		$a2 = "$ SELECT Drafts" wide fullword
		$a3 = "$ UID SEARCH subject \"" wide fullword
		$a4 = "$ APPEND INBOX {" wide fullword
		$a5 = "+FLAGS (\\Deleted)" wide fullword
		$a6 = "$ EXPUNGE" wide fullword
		$a7 = "BODY.PEEK[text]" wide fullword
		$t1 = "change_time" ascii fullword
		$t2 = "ReplaceBytes" ascii fullword
		$t3 = "fcreds" ascii fullword
		$t4 = "screds" ascii fullword
		$t5 = "r_creds" ascii fullword
		$t6 = "comp_id" ascii fullword
		$t7 = "changesecond" wide fullword
		$t8 = "taskkill /F /PID" wide fullword
		$t9 = "cmd.exe" wide fullword

	condition:
		filesize >8KB and filesize <100KB and ( uint16be(0)==0x4D5A) and $dotNet and (3 of ($a*)) and (2 of ($t*))
}