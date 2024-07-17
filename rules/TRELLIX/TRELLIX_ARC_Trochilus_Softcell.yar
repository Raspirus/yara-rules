rule TRELLIX_ARC_Trochilus_Softcell : TROJAN FILE
{
	meta:
		description = "Rule to detect Trochilus malware used in the SoftCell operation"
		author = "Trellix ARC Team"
		id = "81e942ae-936f-5952-8d50-ee8cec74520b"
		date = "2019-06-25"
		modified = "2020-08-14"
		reference = "https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/APT/APT_Operation_SoftCell.yar#L74-L106"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "80a0841a08627acf11707f3aeef4e7c3777aecf04b932755efa618d7e92b0cda"
		score = 75
		quality = 70
		tags = "TROJAN, FILE"
		rule_version = "v1"
		malware_type = "trojan"
		malware_family = "Trojan:W32/Trochilus"
		actor_type = "Apt"
		actor_group = "Unknown"

	strings:
		$s1 = "Shell.dll" fullword ascii
		$s2 = "photo.dat" fullword wide
		$s3 = "VW9HxtV9H|tQ9" fullword ascii
		$s4 = "G6uEGRich7uEG" fullword ascii
		$op0 = { e8 9d ad ff ff ff b6 a8 }
		$op1 = { e8 d4 ad ff ff ff b6 94 }
		$op2 = { e8 ea ad ff ff ff b6 8c }

	condition:
		uint16(0)==0x5a4d and filesize <200KB and (pe.imphash()=="8e13ebc144667958722686cb04ee16f8" and (pe.exports("Entry") and pe.exports("Main")) and all of them )
}