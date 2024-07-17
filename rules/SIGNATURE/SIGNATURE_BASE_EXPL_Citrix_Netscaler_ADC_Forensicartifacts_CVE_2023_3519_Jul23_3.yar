
rule SIGNATURE_BASE_EXPL_Citrix_Netscaler_ADC_Forensicartifacts_CVE_2023_3519_Jul23_3 : CVE_2023_3519 FILE
{
	meta:
		description = "Detects forensic artifacts found after an exploitation of Citrix NetScaler ADC CVE-2023-3519"
		author = "Florian Roth"
		id = "2f40b423-f1da-5711-ac4f-18de77cd52d0"
		date = "2023-07-24"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/citrix-zero-day-espionage"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_citrix_netscaler_adc_exploitation_cve_2023_3519.yar#L43-L61"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e78e1a788503b841ed0f4e5cd415eb35d8911092778120d7fd061ed20820da37"
		score = 70
		quality = 85
		tags = "CVE-2023-3519, FILE"

	strings:
		$x1 = "cat /flash/nsconfig/ns.conf >>" ascii
		$x2 = "cat /nsconfig/.F1.key >>" ascii
		$x3 = "openssl base64 -d < /tmp/" ascii
		$x4 = "cp /usr/bin/bash /var/tmp/bash" ascii
		$x5 = "chmod 4775 /var/tmp/bash"
		$x6 = "pwd;pwd;pwd;pwd;pwd;"
		$x7 = "(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(objectCategory=computer)))"

	condition:
		filesize <10MB and 1 of them
}