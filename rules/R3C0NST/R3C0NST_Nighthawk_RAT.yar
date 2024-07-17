rule R3C0NST_Nighthawk_RAT : FILE
{
	meta:
		description = "Detects Nighthawk RAT"
		author = "Frank Boldewin (@r3c0nst)"
		id = "7a58b8bf-fb14-5758-bc2a-ad2c6fff1216"
		date = "2022-11-30"
		modified = "2022-11-30"
		reference = "https://www.proofpoint.com/us/blog/threat-insight/nighthawk-and-coming-pentest-tool-likely-gain-threat-actor-notice"
		source_url = "https://github.com/fboldewin/YARA-rules//blob/54e9e6899b258b72074b2b4db6909257683240c2/nighthawk.yar#L3-L28"
		license_url = "N/A"
		logic_hash = "5124f7c0186f40cf0a7706e17afe6ba791ca82ac4f4ee940f6fbae5223771a95"
		score = 75
		quality = 90
		tags = "FILE"
		hash1 = "0551ca07f05c2a8278229c1dc651a2b1273a39914857231b075733753cb2b988"
		hash2 = "9a57919cc5c194e28acd62719487c563a8f0ef1205b65adbe535386e34e418b8"
		hash3 = "38881b87826f184cc91559555a3456ecf00128e01986a9df36a72d60fb179ccf"
		hash4 = "f3bba2bfd4ed48b5426e36eba3b7613973226983a784d24d7a20fcf9df0de74e"
		hash5 = "b775a8f7629966592cc7727e2081924a7d7cf83edd7447aa60627a2b67d87c94"

	strings:
		$pattern1 = { 48 8d 0d ?? ?? ?? ?? 51 5a 48 81 c1 ?? ?? ?? ?? 48 81 c2 ?? ?? ?? ?? ff e2 }
		$pattern2 = { 66 03 D2 66 33 D1 66 C1 E2 02 66 33 D1 66 23 D0 0F B7 C1 }
		$pattern3 = { FF 7F 48 3B F0 48 0F 47 F0 48 8D }
		$pattern4 = { 65 48 8B 04 25 30 00 00 00 8B 40 68 49 89 CA 0F 05 C3 }
		$pattern5 = { 48 B8 AA AA AA AA AA AA AA 02 48 ?? ?? ?? ?? 0F 84 }
		$pattern6 = { 65 48 8B 04 25 30 00 00 00 48 8B 80 }

	condition:
		uint16(0)==0x5A4D and filesize <2MB and (3 of ($pattern*) or (pe.section_index(".profile") and pe.section_index(".detourc") and pe.section_index(".detourd")))
}