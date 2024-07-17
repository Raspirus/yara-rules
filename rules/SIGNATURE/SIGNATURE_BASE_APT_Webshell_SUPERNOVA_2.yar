import "pe"


rule SIGNATURE_BASE_APT_Webshell_SUPERNOVA_2 : FILE
{
	meta:
		description = "This rule is looking for specific strings related to SUPERNOVA. SUPERNOVA is a .NET web shell backdoor masquerading as a legitimate SolarWinds web service handler. SUPERNOVA inspects and responds to HTTP requests with the appropriate HTTP query strings, Cookies, and/or HTML form values (e.g. named codes, class, method, and args)."
		author = "FireEye"
		id = "c39bf9ba-fd62-5619-92b6-1633375ef197"
		date = "2020-12-14"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_solarwinds_sunburst.yar#L100-L118"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "96e344bd2ba3ee07784852db3e9935352762c2fa7b6be88f00cac10a90706ffc"
		score = 85
		quality = 83
		tags = "FILE"

	strings:
		$dynamic = "DynamicRun"
		$solar = "Solarwinds" nocase
		$string1 = "codes"
		$string2 = "clazz"
		$string3 = "method"
		$string4 = "args"

	condition:
		uint16(0)==0x5a4d and uint32( uint32(0x3C))==0x00004550 and filesize <10KB and 3 of ($string*) and $dynamic and $solar
}