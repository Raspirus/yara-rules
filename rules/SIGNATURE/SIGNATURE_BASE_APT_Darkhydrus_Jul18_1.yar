rule SIGNATURE_BASE_APT_Darkhydrus_Jul18_1 : FILE
{
	meta:
		description = "Detects strings found in malware samples in APT report in DarkHydrus"
		author = "Florian Roth (Nextron Systems)"
		id = "fbd001c0-43c9-5429-84d6-7f62eadd8ff3"
		date = "2018-07-28"
		modified = "2023-12-05"
		reference = "https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_darkhydrus.yar#L13-L29"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "2c39f2e6b37e6422984275f45a2917891c3b482d137dbbfd6293088c2f2dacc3"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "99541ab28fc3328e25723607df4b0d9ea0a1af31b58e2da07eff9f15c4e6565c"

	strings:
		$x1 = "Z:\\devcenter\\aggressor\\" ascii

	condition:
		uint16(0)==0x5a4d and filesize <600KB and (pe.imphash()=="d3666d1cde4790b22b44ec35976687fb" or 1 of them )
}