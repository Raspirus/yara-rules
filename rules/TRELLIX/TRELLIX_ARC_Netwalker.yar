rule TRELLIX_ARC_Netwalker : RANSOMWARE FILE
{
	meta:
		description = "Rule based on code overlap in RagnarLocker ransomware"
		author = "McAfee ATR team"
		id = "80097a40-534a-5e1b-8fde-e4d832d76698"
		date = "2020-06-14"
		modified = "2020-11-20"
		reference = "https://github.com/advanced-threat-research/Yara-Rules/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_netwalker.yar#L49-L75"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "8c56ebed9e097d294045de46942c708da9ba7e01475dcecb0c3d41fcc8004780"
		score = 75
		quality = 70
		tags = "RANSOMWARE, FILE"
		rule_version = "v1"
		malware_type = "ransomware"
		actor_group = "Unknown"

	strings:
		$0 = {C88BF28B4330F76F3803C88B434813F2F76F2003C88B433813F2F76F3003C88B434013F2F76F2803C88B432813F2F76F4003C8894D6813F289756C8B4338F76F388BC88BF28B4328F76F4803C88B434813F2F76F2803C88B433013F2F76F400FA4CE}
		$1 = {89542414895424108BEA8BDA8BFA423C22747C3C5C75588A023C5C744F3C2F744B3C2274473C6275078D5702B008EB3F3C6675078D5302B00CEB343C6E75078D5502B00AEB293C72750B8B542410B00D83C202EB1A3C74750B8B542414B00983C2}
		$2 = {C8894D7013F28975748B4338F76F408BC88BF28B4340F76F3803C88B433013F2F76F4803C88B434813F2F76F3003C8894D7813F289757C8B4348F76F388BC88BF28B4338F76F4803C88B434013F2F76F400FA4CE}
		$3 = {C07439473C2F75E380FB2A74DEEB2D8D4ABF8D422080F9190FB6D80FB6C28AD60F47D88AC6042080EA410FB6C880FA190FB6C60F47C83ACB754B46478A1684D2}
		$4 = {8B433013F2F76F0803C88B432013F2F76F1803C88B0313F2F76F3803C88B430813F2F76F3003C88B433813F2F72F03C8894D3813F289753C8B4338F76F088BC8}
		$5 = {F73101320E32213234329832E3320C332D334733643383339133A833BD33053463347C34543564358335AE36C3362937E9379A39BA390A3A203A443A183B2B3B}
		$6 = {8B431813F2F76F4803C88B432813F2F76F3803C88B434013F2F76F200FA4CE0103C903C88B432013F2F76F4003C88B433013F2F76F3003C8894D6013F2897564}

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and all of them
}