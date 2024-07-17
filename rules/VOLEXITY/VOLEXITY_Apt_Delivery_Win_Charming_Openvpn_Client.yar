rule VOLEXITY_Apt_Delivery_Win_Charming_Openvpn_Client : CHARMINGCYPRESS FILE
{
	meta:
		description = "Detects a fake OpenVPN client developed by CharmingCypress."
		author = "threatintel@volexity.com"
		id = "b69fdd72-4a55-5e83-b754-401fe9339007"
		date = "2023-10-17"
		modified = "2023-10-27"
		reference = "TIB-20231027"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2024/2024-02-13 CharmingCypress/rules.yar#L287-L310"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		logic_hash = "02596a62cb1ba17ecabef0ae93f434e4774b00422a6da2106a2bc4c59d2f8077"
		score = 75
		quality = 80
		tags = "CHARMINGCYPRESS, FILE"
		hash1 = "2d99755d5cd25f857d6d3aa15631b69f570d20f95c6743574f3d3e3e8765f33c"
		os = "win"
		os_arch = "all"
		scan_context = "file"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 9768
		version = 2

	strings:
		$s1 = "DONE!"
		$s2 = "AppCore.dll"
		$s3 = "ultralight@@"

	condition:
		all of ($s*)
}