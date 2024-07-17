rule DITEKSHEN_INDICATOR_RMM_Pdqconnect_Agent_CERT : FILE
{
	meta:
		description = "Detects PDQ Connect Agent by (default) certificate. Review RMM Inventory"
		author = "ditekSHen"
		id = "7e830cf0-8f47-5b38-85cd-9777a6878cf1"
		date = "2023-11-16"
		modified = "2023-11-16"
		reference = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_rmm.yar#L229-L243"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "373a32b8bfd8c4295ba0c0302a217ccfbb7c7c616f91035097adbc5384b8afdb"
		score = 75
		quality = 75
		tags = "FILE"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].issuer contains "DigiCert, Inc." and pe.signatures[i].subject contains "PDQ.com Corporation")
}