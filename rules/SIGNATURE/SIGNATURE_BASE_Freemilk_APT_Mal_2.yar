import "pe"


rule SIGNATURE_BASE_Freemilk_APT_Mal_2 : FILE
{
	meta:
		description = "Detects malware from FreeMilk campaign"
		author = "Florian Roth (Nextron Systems)"
		id = "ef5f400c-16f8-5374-af16-c8530ddb87ee"
		date = "2017-10-05"
		modified = "2023-12-05"
		reference = "https://researchcenter.paloaltonetworks.com/2017/10/unit42-freemilk-highly-targeted-spear-phishing-campaign/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_freemilk.yar#L41-L60"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ad2cc04542e93add3e7856574d4de5aa371cc31542f87b1e90d30e12e0149341"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "7f35521cdbaa4e86143656ff9c52cef8d1e5e5f8245860c205364138f82c54df"

	strings:
		$s1 = "failed to take the screenshot. err: %d" fullword ascii
		$s2 = "runsample" fullword wide
		$s3 = "%s%02X%02X%02X%02X%02X%02X:" fullword wide
		$s4 = "win-%d.%d.%d-%d" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <400KB and (pe.imphash()=="b86f7d2c1c182ec4c074ae1e16b7a3f5" or all of them )
}