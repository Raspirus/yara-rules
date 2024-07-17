rule ARKBIRD_SOLG_APT_UNC2452_Webshell_Chopper_Mar_2021_1 : FILE
{
	meta:
		description = "Detect exploit listener in the exchange configuration for Webshell Chopper used by UNC2452 group"
		author = "Arkbird_SOLG"
		id = "174af8e1-0df0-5ad7-ac7d-a208f64cb765"
		date = "2021-03-07"
		modified = "2021-03-07"
		reference = "Internal Research"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-03-07/UNC2452/APT_UNC2452_Webshell_Chopper_Mar_2021_1.yar#L1-L26"
		license_url = "N/A"
		logic_hash = "77bd7e5c10aa9cf2b407b37a76954b4eed163e36653e1fb3cde5de853f824cf0"
		score = 75
		quality = 73
		tags = "FILE"

	strings:
		$l1 = { 20 68 74 74 70 3a 2f 2f ?? 2f 3c 73 63 72 69 70 74 20 4c 61 6e 67 75 61 67 65 3d 22 63 23 22 20 72 75 6e 61 74 3d 22 73 65 72 76 65 72 22 3e 76 6f 69 64 20 50 61 67 65 5f 4c 6f 61 64 28 6f 62 6a 65 63 74 20 73 65 6e 64 65 72 2c 20 45 76 65 6e 74 41 72 67 73 20 65 29 7b 69 66 20 28 52 65 71 75 65 73 74 2e 46 69 6c 65 73 2e 43 6f 75 6e 74 21 3d 30 29 20 7b 20 52 65 71 75 65 73 74 2e 46 69 6c 65 73 5b 30 5d 2e 53 61 76 65 41 73 28 53 65 72 76 65 72 2e 4d 61 70 50 61 74 68 28 22 [5-14] 22 29 29 3b 7d 7d 3c 2f 73 63 72 69 70 74 3e }
		$l2 = { 68 74 74 70 3a 2f 2f ?? 2f 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 4a 53 63 72 69 70 74 22 20 72 75 6e 61 74 3d 22 73 65 72 76 65 72 22 3e 66 75 6e 63 74 69 6f 6e 20 50 61 67 65 5f 4c 6f 61 64 28 29 7b 65 76 61 6c 28 [-] 2c 22 75 6e 73 61 66 65 22 29 3b 7d 3c 2f 73 63 72 69 70 74 3e }
		$c1 = { 5c 4f 41 42 20 28 44 65 66 61 75 6c 74 20 57 65 62 20 53 69 74 65 29 }
		$c2 = "ExternalUrl" fullword ascii
		$c3 = { 49 49 53 3a 2f 2f [10-30] 2f 57 33 53 56 43 2f [1-3] 2f 52 4f 4f 54 2f 4f 41 42 }
		$c4 = "FrontEnd\\HttpProxy\\OAB" fullword ascii
		$c5 = "/Configuration/Schema/ms-Exch-OAB-Virtual-Directory" fullword ascii

	condition:
		filesize >1KB and 1 of ($l*) and 3 of ($c*)
}