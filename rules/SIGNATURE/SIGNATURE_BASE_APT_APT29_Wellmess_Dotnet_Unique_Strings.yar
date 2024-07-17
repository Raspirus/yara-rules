
rule SIGNATURE_BASE_APT_APT29_Wellmess_Dotnet_Unique_Strings : FILE
{
	meta:
		description = "Rule to detect WellMess .NET samples based on unique strings and function/variable names"
		author = "NCSC"
		id = "7a058ec7-f795-5226-b511-ff469a969ee6"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt29_grizzly_steppe.yar#L120-L136"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "2285a264ffab59ab5a1eb4e2b9bcab9baf26750b6c551ee3094af56a4442ac41"
		logic_hash = "90e8480aa50e18202007bcffdc8348290ad0ac0588c924b4f75ea425a6cae32d"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "HealthInterval" wide
		$s2 = "Hello from Proxy" wide
		$s3 = "Start bot:" wide
		$s4 = "FromNormalToBase64" ascii
		$s5 = "FromBase64ToNormal" ascii
		$s6 = "WellMess" ascii

	condition:
		uint16(0)==0x5a4d and uint16( uint16(0x3c))==0x4550 and 3 of them
}