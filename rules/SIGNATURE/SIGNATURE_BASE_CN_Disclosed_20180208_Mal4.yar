rule SIGNATURE_BASE_CN_Disclosed_20180208_Mal4 : FILE
{
	meta:
		description = "Detects malware from disclosed CN malware set"
		author = "Florian Roth (Nextron Systems)"
		id = "6165caf5-157f-5381-a77e-6ed775187ab1"
		date = "2018-02-08"
		modified = "2023-12-05"
		reference = "https://www.virustotal.com/graph/#/selected/n120z79z208z189/drawer/graph-details"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_cn_campaign_njrat.yar#L124-L138"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "044901271adb06036e7d5aa8f2b6f893be10445bee95453c293d0025994e8d21"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "f7549c74f09be7e4dbfb64006e535b9f6d17352e236edc2cdb102ec3035cf66e"

	strings:
		$s1 = "Microsoft .Net Framework COM+ Support" fullword ascii
		$s2 = "Microsoft .NET and Windows XP COM+ Integration with SOAP" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and 1 of them and pe.exports("SPACE")
}