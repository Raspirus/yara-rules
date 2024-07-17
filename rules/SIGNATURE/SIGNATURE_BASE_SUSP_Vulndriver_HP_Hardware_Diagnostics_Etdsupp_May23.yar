
rule SIGNATURE_BASE_SUSP_Vulndriver_HP_Hardware_Diagnostics_Etdsupp_May23 : FILE
{
	meta:
		description = "Detects vulnerable versions of the HP Hardware Diagnostics driver (etdsupp.sys) based on PE metadata info"
		author = "X__Junior (Nextron Systems)"
		id = "8f838e4f-3e3e-5131-9d67-e49f6848bb37"
		date = "2023-05-12"
		modified = "2023-12-05"
		reference = "https://github.com/alfarom256/HPHardwareDiagnostics-PoC/tree/main/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/susp_vulndriver_hp_hardware_diagnostics_etdsupp_may23.yar#L1-L16"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "f744abb99c97d98e4cd08072a897107829d6d8481aee96c22443f626d00f4145"
		logic_hash = "bb50f591e49b1b0b08ccbe4ca5cb3685d8f358e51e6d6f77677bc05701f6b301"
		score = 65
		quality = 85
		tags = "FILE"

	strings:
		$s1 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 65 00 74 00 64 00 73 00 75 00 70 00 70 00 2e 00 73 00 79 00 73 00}
		$s2 = "etdsupp.pdb"
		$s3 = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff]{2}[\x00-\x11]\x00[\x00-\xff]{4}|\x00\x00\x12\x00\x00\x00\x00\x00)/

	condition:
		uint16(0)==0x5a4d and int16 ( uint32(0x3C)+0x5c)==0x0001 and filesize <100KB and all of them
}