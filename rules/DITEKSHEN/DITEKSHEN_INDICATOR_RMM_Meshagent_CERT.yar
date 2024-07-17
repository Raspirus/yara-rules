rule DITEKSHEN_INDICATOR_RMM_Meshagent_CERT : FILE
{
	meta:
		description = "Detects Mesh Agent by (default) certificate. Review RMM Inventory"
		author = "ditekSHen"
		id = "b4b52faa-53a5-5ecf-bff8-984994449ee0"
		date = "2023-11-16"
		modified = "2023-11-16"
		reference = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_rmm.yar#L29-L42"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "d8ac3aec723a87146be99aefbde5642d095d8d41f69c6f5e9981c39104790d33"
		score = 75
		quality = 75
		tags = "FILE"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].issuer contains "MeshCentralRoot-")
}