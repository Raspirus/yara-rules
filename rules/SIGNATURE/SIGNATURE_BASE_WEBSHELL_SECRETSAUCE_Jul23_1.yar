
rule SIGNATURE_BASE_WEBSHELL_SECRETSAUCE_Jul23_1 : CVE_2023_3519 FILE
{
	meta:
		description = "Detects SECRETSAUCE PHP webshells (found after an exploitation of Citrix NetScaler ADC CVE-2023-3519)"
		author = "Florian Roth"
		id = "db0542e7-648e-5f60-9838-e07498f58b51"
		date = "2023-07-24"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/citrix-zero-day-espionage"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_citrix_netscaler_adc_exploitation_cve_2023_3519.yar#L79-L100"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c762d46ae43a3e10453c2ee17039812a06086ac85bdb000cf8308f5196a9dee2"
		score = 85
		quality = 85
		tags = "CVE-2023-3519, FILE"

	strings:
		$sa1 = "for ($x=0; $x<=1; $x++) {" ascii
		$sa2 = "$_REQUEST[" ascii
		$sa3 = "@eval" ascii
		$sb1 = "public $cmd;" ascii
		$sb2 = "return @eval($a);" ascii
		$sb3 = "$z->run($z->get('openssl_public_decrypt'));"

	condition:
		filesize <100KB and ( all of ($sa*) or 2 of ($sb*))
}