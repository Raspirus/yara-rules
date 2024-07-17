rule SIGNATURE_BASE_SUSP_LNX_Base64_Download_Exec_Apr24 : SCRIPT
{
	meta:
		description = "Detects suspicious base64 encoded shell commands used for downloading and executing further stages"
		author = "Paul Hager"
		id = "df8dddef-3c49-500c-abc8-7f7de5aa69ae"
		date = "2024-04-18"
		modified = "2024-04-24"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/vuln_paloalto_cve_2024_3400_apr24.yar#L48-L65"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "90b7781812b4078550b0d66ba020b3bb0a8217f2de03492af98db6c619f31929"
		score = 75
		quality = 85
		tags = "SCRIPT"

	strings:
		$sa1 = "curl http" base64
		$sa2 = "wget http" base64
		$sb1 = "chmod 777 " base64
		$sb2 = "/tmp/" base64

	condition:
		1 of ($sa*) and all of ($sb*)
}