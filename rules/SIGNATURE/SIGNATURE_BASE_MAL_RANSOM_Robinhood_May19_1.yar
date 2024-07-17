rule SIGNATURE_BASE_MAL_RANSOM_Robinhood_May19_1 : FILE
{
	meta:
		description = "Detects RobinHood Ransomware"
		author = "Florian Roth (Nextron Systems)"
		id = "7199c0de-c925-5399-8fa6-852604190a21"
		date = "2019-05-15"
		modified = "2023-12-05"
		reference = "https://twitter.com/BThurstonCPTECH/status/1128489465327030277"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_ransom_robinhood.yar#L2-L21"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "5eef71b94f2488dceff80ec2daba689c12d13b2742ba9ae5ead58711339d6026"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "21cb84fc7b33e8e31364ff0e58b078db8f47494a239dc3ccbea8017ff60807e3"

	strings:
		$s1 = ".enc_robbinhood" ascii
		$s2 = "c:\\windows\\temp\\pub.key" ascii fullword
		$s3 = "cmd.exe /c net use * /DELETE /Y" ascii
		$s4 = "sc.exe stop SQLAgent$SQLEXPRESS" nocase
		$s5 = "main.EnableShadowFucks" nocase
		$s6 = "main.EnableRecoveryFCK" nocase
		$s7 = "main.EnableLogLaunders" nocase
		$s8 = "main.EnableServiceFuck" nocase

	condition:
		uint16(0)==0x5a4d and filesize <8000KB and 1 of them
}