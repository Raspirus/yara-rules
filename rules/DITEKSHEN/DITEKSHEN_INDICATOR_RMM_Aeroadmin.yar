rule DITEKSHEN_INDICATOR_RMM_Aeroadmin : FILE
{
	meta:
		description = "Detects AeroAdmin. Review RMM Inventory"
		author = "ditekSHen"
		id = "0f69c6da-40e4-5952-b6f9-ed401279eb9e"
		date = "2023-11-16"
		modified = "2023-11-16"
		reference = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_rmm.yar#L421-L442"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "a0a9e15f31b6b06fbc749b863563c30351c775c1b1d17952013670e7e1d68c41"
		score = 75
		quality = 75
		tags = "FILE"
		clamav1 = "INDICATOR.Win.RMM.AeroAdmin"

	strings:
		$s1 = "\\AeroAdmin" wide
		$s2 = ".aeroadmin.com" ascii wide
		$s3 = "XAeroadminAppRestarter" wide
		$s4 = "SYSTEM\\ControlSet001\\Control\\SafeBoot\\Network\\AeroadminService" wide
		$s5 = "AeroAdmin {}" ascii
		$s6 = "FAeroAdmin.cpp" fullword ascii
		$s7 = "Referer: http://900100.net" ascii
		$s8 = "POST /sims/sims_new.php" ascii
		$s9 = "aeroadmin.pdb" ascii

	condition:
		uint16(0)==0x5a4d and 4 of them
}