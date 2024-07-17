rule SIGNATURE_BASE_MAL_Ramnit_May19_1 : FILE
{
	meta:
		description = "Detects Ramnit malware"
		author = "Florian Roth (Nextron Systems)"
		id = "f8fa3557-556e-5680-9f1a-2ecf118ade75"
		date = "2019-05-31"
		modified = "2023-12-05"
		reference = "https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_nansh0u.yar#L67-L78"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "51d574f457c37eba3c29f869e03244b9471be6f6c8319aa0ddfad34be748eb53"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "d7ec3fcd80b3961e5bab97015c91c843803bb915c13a4a35dfb5e9bdf556c6d3"

	condition:
		uint16(0)==0x5a4d and filesize <300KB and pe.imphash()=="500cd02578808f964519eb2c85153046"
}