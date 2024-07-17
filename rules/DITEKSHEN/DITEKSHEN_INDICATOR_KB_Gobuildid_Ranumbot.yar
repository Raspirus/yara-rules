rule DITEKSHEN_INDICATOR_KB_Gobuildid_Ranumbot : FILE
{
	meta:
		description = "Detects Golang Build IDs in known bad samples"
		author = "ditekSHen"
		id = "f368cd9d-f974-56cf-a2b5-bd300f30cedc"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_knownbad_id.yar#L1624-L1633"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "c3d0ba55ca2be1b11ebf1b82490c5d26f2b35958b31a7e55892e27f24bf4118f"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "Go build ID: \"hOhuOA4W60aBBRoFQTDA/dl9DuLAgEcabYGK6ZT2t/ECsse3630jV_957OqqK3/ZRA_JRPFzxutK16zlEcM\"" ascii
		$s2 = "Go build ID: \"NivDrAudWE-E6xtBXeww/3pv6fDzDqt4v0YxoTkPt/8vd79TNE-9Bt38ftxf_V/_GNqnqEUsRf-WTSmn8dM\"" ascii

	condition:
		uint16(0)==0x5a4d and 1 of them
}