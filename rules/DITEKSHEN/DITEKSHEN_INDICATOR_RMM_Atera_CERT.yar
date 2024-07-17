import "pe"


rule DITEKSHEN_INDICATOR_RMM_Atera_CERT : FILE
{
	meta:
		description = "Detects Atera by certificate. Review RMM Inventory"
		author = "ditekSHen"
		id = "a5ccb684-1e28-51c8-a4d6-0b5abba97de0"
		date = "2023-11-16"
		modified = "2023-11-16"
		reference = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_rmm.yar#L368-L383"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "f51fef767cd529271f06d578146634e1ab5ee5ac3ffb829cbaa870e7c69ca3f6"
		score = 75
		quality = 75
		tags = "FILE"
		clamav1 = "INDICATOR.Win.RMM.Atera"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].issuer contains "DigiCert" and pe.signatures[i].subject contains "Atera Networks Ltd")
}