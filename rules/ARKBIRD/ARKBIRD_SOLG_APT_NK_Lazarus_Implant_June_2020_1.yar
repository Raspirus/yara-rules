rule ARKBIRD_SOLG_APT_NK_Lazarus_Implant_June_2020_1 : FILE
{
	meta:
		description = "Detect Lazarus implant June 2020"
		author = "Arkbird_SOLG"
		id = "602c33f2-1e34-5267-9154-ada2d6edc64b"
		date = "2020-06-28"
		modified = "2020-06-28"
		reference = "https://twitter.com/ccxsaber/status/1277064824434745345"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-06-28/APT_NK_Lazarus_Implant_June_2020_1.yar#L3-L23"
		license_url = "N/A"
		logic_hash = "29b6b8d3bdd47707854ed0dc00808d6352934950a8e7244450df78422ff3cb15"
		score = 75
		quality = 73
		tags = "FILE"
		hash1 = "21afaceee5fab15948a5a724222c948ad17cad181bf514a680267abcce186831"

	strings:
		$s1 = "Upgrade.exe" fullword ascii
		$s2 = "ver=%d&timestamp=%lu" fullword ascii
		$s3 = "_update.php" fullword ascii
		$s4 = "Dorusio Wallet 2.1.0 (Check Update Windows)" fullword wide
		$s5 = "Content-Type: application/x-www-form-urlencoded" fullword ascii
		$s6 = "CONOUT$" fullword ascii
		$s7 = "D$8fD;i" fullword ascii
		$s8 = "WinHttpOpenRequest" fullword ascii
		$s9 = "HTTP/1.0" fullword ascii
		$s10 = "POST" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <30KB and (pe.imphash()=="565005404f00b7def4499142ade5e3dd" or 6 of them )
}