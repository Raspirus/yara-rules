rule SIGNATURE_BASE_APT_Darkhydrus_Jul18_3 : FILE
{
	meta:
		description = "Detects strings found in malware samples in APT report in DarkHydrus"
		author = "Florian Roth (Nextron Systems)"
		id = "1f766b49-3173-5f8a-ba52-a9ce9000be79"
		date = "2018-07-28"
		modified = "2023-12-05"
		reference = "https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_darkhydrus.yar#L50-L67"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "0f3425322846e6064ec2576ad4e73061fbec3e4400de54d05fe07b8ad2a31f92"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "c8b3d4b6acce6b6655e17255ef7a214651b7fc4e43f9964df24556343393a1a3"

	strings:
		$s2 = "Ws2_32.dll" fullword ascii
		$s3 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0)" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and (pe.imphash()=="478eacfbe2b201dabe63be53f34148a5" or all of them )
}