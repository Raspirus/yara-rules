import "pe"


rule SIGNATURE_BASE_APT_NK_MAL_M_Hunting_VEILEDSIGNAL_2 : FILE
{
	meta:
		description = "Detects VEILEDSIGNAL malware"
		author = "Mandiant"
		id = "1b96c2f0-1c57-593e-9630-a72d43eb857e"
		date = "2023-04-20"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_nk_tradingtech_apr23.yar#L57-L76"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "62f74faa8f136f4dc63a4b703cffcb97b438cc4f180d5d127d1fc4b86d3cd1d1"
		score = 75
		quality = 85
		tags = "FILE"
		disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"
		hash1 = "404b09def6054a281b41d309d809a428"

	strings:
		$sb1 = { C1 E0 05 4D 8? [2] 33 D0 45 69 C0 7D 50 BF 12 8B C2 41 FF C2 C1 E8 07 33 D0 8B C2 C1 E0 16 41 81 C0 87 D6 12 00 }
		$si1 = "CryptBinaryToStringA" fullword
		$si2 = "BCryptGenerateSymmetricKey" fullword
		$si3 = "CreateThread" fullword
		$ss1 = "ChainingModeGCM" wide
		$ss2 = "__tutma" fullword

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and ( uint16( uint32(0x3C)+0x18)==0x020B) and all of them
}