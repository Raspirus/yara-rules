rule DITEKSHEN_INDICATOR_RMM_Fleetdeck_Commander_SVC : FILE
{
	meta:
		description = "Detects FleetDeck Commander SVC. Review RMM Inventory"
		author = "ditekSHen"
		id = "c03b61b4-36d0-5d38-9af8-e78b9930231f"
		date = "2023-11-16"
		modified = "2023-11-16"
		reference = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_rmm.yar#L145-L162"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "20bd69df3d058c24f83af312671cf249a3f26f54ef2e60f6b5b48a5bdb21b68b"
		score = 75
		quality = 75
		tags = "FILE"
		clamav1 = "INDICATOR.Win.RMM.FleetDeckCommander-SVC"

	strings:
		$s1 = "fleetdeckfork/execfuncargs(" ascii
		$s2 = "REG ADD HKEY_CLASSES_ROOT\\%s /V \"URL Protocol\" /T REG_SZ /F" ascii
		$s3 = "proceed: *.fleetdeck.io" ascii
		$s4 = "fleetdeck.io/prototype3/commander_svc" ascii
		$s5 = "commanderupdate.fleetdeck.io" ascii

	condition:
		uint16(0)==0x5a4d and 4 of them
}