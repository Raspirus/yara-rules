import "pe"


rule SIGNATURE_BASE_SUSP_PDB_CN_Threat_Actor_May19_1 : FILE
{
	meta:
		description = "Detects PDB path user name used by Chinese threat actors"
		author = "Florian Roth (Nextron Systems)"
		id = "fc6969ed-5fc1-5b3b-9659-c6fc1c9e2f9c"
		date = "2019-05-31"
		modified = "2023-12-05"
		reference = "https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_nansh0u.yar#L52-L65"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "adcfe3d4bc6fcaf6be4f70c91fb2150bfa2d61f1ba84f96a0bf0c39ed0380b6a"
		score = 65
		quality = 85
		tags = "FILE"
		hash1 = "01c3882e8141a25abe37bb826ab115c52fd3d109c4a1b898c0c78cee8dac94b4"

	strings:
		$x1 = "C:\\Users\\zcg\\Desktop\\" ascii

	condition:
		uint16(0)==0x5a4d and filesize <400KB and 1 of them
}