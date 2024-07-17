rule DITEKSHEN_INDICATOR_RMM_Fleetdeck_CERT : FILE
{
	meta:
		description = "Detects FleetDeck agent by (default) certificate. Review RMM Inventory"
		author = "ditekSHen"
		id = "49a6b0bb-599a-54b0-85bc-b2f6849e3ae8"
		date = "2023-11-16"
		modified = "2023-11-16"
		reference = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_rmm.yar#L180-L198"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "8f72713eb4a5d9d32629351b937eee7de5d83abe1cd409cd8c3a8c9c52e6e490"
		score = 75
		quality = 75
		tags = "FILE"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : ((pe.signatures[i].issuer contains "Sectigo Limited" or pe.signatures[i].issuer contains "COMODO CA Limited") and pe.signatures[i].subject contains "FleetDeck Inc")
}