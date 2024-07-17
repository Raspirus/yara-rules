rule VOLEXITY_Trojan_Backwash_Iis_Scout : XEGROUP
{
	meta:
		description = "Simple backdoor which collects information about the IIS server it is installed on. It appears to the attacker refers to this components as 'XValidate' - i.e. to validate infected machines."
		author = "threatintel@volexity.com"
		id = "1f768b39-21a0-574d-9043-5104540003f7"
		date = "2021-11-17"
		modified = "2021-12-07"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2021/2021-12-06 - XEGroup/indicators/yara.yar#L42-L66"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		logic_hash = "18c4e338905ff299d75534006037e63a8f9b191f062cc97b0592245518015f88"
		score = 75
		quality = 80
		tags = "XEGROUP"
		hash1 = "6f44a9c13459533a1f3e0b0e698820611a18113c851f763797090b8be64fd9d5"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$s1 = "SOAPRequest" ascii
		$s2 = "requestServer" ascii
		$s3 = "getFiles" ascii
		$s4 = "APP_POOL_CONFIG" wide
		$s5 = "<virtualDirectory" wide
		$s6 = "stringinstr" ascii
		$s7 = "504f5354" wide
		$s8 = "XValidate" ascii
		$s9 = "XEReverseShell" ascii
		$s10 = "XERsvData" ascii

	condition:
		6 of them
}