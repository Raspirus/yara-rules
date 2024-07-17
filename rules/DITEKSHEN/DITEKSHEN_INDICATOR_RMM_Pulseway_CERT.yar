rule DITEKSHEN_INDICATOR_RMM_Pulseway_CERT : FILE
{
	meta:
		description = "Detects PulseWay by (default) certificate. Review RMM Inventory"
		author = "ditekSHen"
		id = "e00f51dc-261e-5a38-89ed-1899d9b522d4"
		date = "2023-11-16"
		modified = "2023-11-16"
		reference = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_rmm.yar#L288-L302"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "c667caa9b7de4b166630c66e5162071948fa93c68b1cdb3038fce28e13dcb1a9"
		score = 75
		quality = 75
		tags = "FILE"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].issuer contains "DigiCert, Inc." and pe.signatures[i].subject contains "MMSOFT Design Ltd.")
}