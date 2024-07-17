
rule HARFANGLAB_Muddywater_Ateraagent_Operators : FILE
{
	meta:
		description = "Detect Atera Agent abused by MuddyWater"
		author = "HarfangLab"
		id = "1494a0da-92de-5cfb-a870-325d02e2cdfb"
		date = "2024-04-17"
		modified = "2024-05-16"
		reference = "TRR240402"
		source_url = "https://github.com/HarfangLab/iocs/blob/911b0f27d123986b25ad00cc0e7d94a52435cb15/TRR240402/trr240402_yara.yar#L1-L33"
		license_url = "N/A"
		hash = "9b49d6640f5f0f1d68f649252a96052f1d2e0822feadd7ebe3ab6a3cadd75985"
		logic_hash = "63d5d3a6723191dccd20c8d9f25607df512b91f57ac891ef8c87b2dd107ee5a2"
		score = 75
		quality = 80
		tags = "FILE"
		context = "file"

	strings:
		$s1 = "COMPANYID001Q3000009snPyIAIACCOUNTID"
		$s2 = "COMPANYID001Q3000006FpmoIACACCOUNTID"
		$s3 = "COMPANYID001Q3000008IyacIACACCOUNTID"
		$s4 = "COMPANYID001Q3000009QoSEIA0ACCOUNTID"
		$s5 = "COMPANYID001Q30000023c7iIAAACCOUNTID"
		$s6 = "COMPANYID001Q3000008qXbDIAUACCOUNTID"
		$s7 = "COMPANYID001Q3000008cfLjIAIACCOUNTID"
		$s8 = "COMPANYID001Q3000007hJubIAEACCOUNTID"
		$s9 = "COMPANYID001Q3000008ryO3IAIACCOUNTID"
		$s10 = "COMPANYID001Q300000A5nnAIARACCOUNTID"
		$s11 = "COMPANYID001Q3000008JfioIACACCOUNTID"
		$s12 = "COMPANYID001Q300000BeUp3IAFACCOUNTID"
		$s13 = "COMPANYID001Q3000005gMamIAEACCOUNTID"
		$s15 = "mrrobertcornish@gmail.comINTEGRATORLOGINCOMPANYID"
		$cert1 = { 0A 28 49 99 78 E5 89 8D F4 0A 23 8E B8 A5 52 E8 }
		$cert2 = { 06 7F 60 47 95 66 24 A7 15 99 61 74 3D 81 94 93 }

	condition:
		filesize >1MB and filesize <4MB and ( uint16be(0)==0xD0CF) and any of ($s*) and any of ($cert*)
}