import "pe"


rule DITEKSHEN_INDICATOR_RMM_Aeroadmin_CERT : FILE
{
	meta:
		description = "Detects AeroAdmin by certificate. Review RMM Inventory"
		author = "ditekSHen"
		id = "ca34fd3c-eb76-57e3-8b62-ab0d0c9ec7b3"
		date = "2023-11-16"
		modified = "2023-11-16"
		reference = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_rmm.yar#L444-L461"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "f1fe2d2bb6a8afd25fc5ee7a60fe5a931484591bafab24c5d488c7f0483e248a"
		score = 75
		quality = 75
		tags = "FILE"
		clamav1 = "INDICATOR.Win.RMM.AeroAdmin"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].issuer contains "GlobalSign" and (pe.signatures[i].subject contains "Aeroadmin LLC" or pe.signatures[i].subject contains "@aeroadmin.com"))
}