import "pe"


rule SIGNATURE_BASE_HKTL_CN_Prochook_May19_1 : FILE
{
	meta:
		description = "Detects hacktool used by Chinese threat groups"
		author = "Florian Roth (Nextron Systems)"
		id = "ae4e2613-8254-5ea6-af88-2f08ebe4da33"
		date = "2019-05-31"
		modified = "2023-12-05"
		reference = "https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_nansh0u.yar#L38-L49"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "de55990c130702a05e96ee769707a81ce0ec58a515d75a9a99b20265ce3db682"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "02ebdc1ff6075c15a44711ccd88be9d6d1b47607fea17bef7e5e17f8da35293e"

	condition:
		uint16(0)==0x5a4d and filesize <300KB and pe.imphash()=="343d580dd50ee724746a5c28f752b709"
}