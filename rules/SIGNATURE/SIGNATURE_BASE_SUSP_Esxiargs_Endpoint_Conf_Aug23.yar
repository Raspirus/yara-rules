
rule SIGNATURE_BASE_SUSP_Esxiargs_Endpoint_Conf_Aug23 : FILE
{
	meta:
		description = "Detects indicators found in endpoint.conf files as modified by actors in the ESXiArgs campaign"
		author = "Florian Roth"
		id = "3e0b5dbf-7c5b-5599-823a-ce35fbdbe64b"
		date = "2023-08-04"
		modified = "2023-12-05"
		reference = "https://www.bleepingcomputer.com/forums/t/782193/esxi-ransomware-help-and-support-topic-esxiargs-args-extension/page-47"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/mal_ransom_esxi_attacks_feb23.yar#L103-L120"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "794d460eec0e2f0b48e6ced94b125a1e48acde6be6281866e0b4a2ae6c2d3b51"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$a1 = "/client/clients.xml" ascii
		$a2 = "/var/run/vmware/proxy-sdk-tunnel" ascii fullword
		$a3 = "redirect" ascii fullword
		$a4 = "allow" ascii fullword
		$s1 = " local 8008 allow allow"

	condition:
		filesize <2KB and all of them
}