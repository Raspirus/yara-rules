
rule SIGNATURE_BASE_SUSP_IIS_Config_Proxyshell_Artifacts : FILE
{
	meta:
		description = "Detects suspicious virtual directory configured in IIS pointing to a ProgramData folder (as found in attacks against Exchange servers in August 2021)"
		author = "Florian Roth (Nextron Systems)"
		id = "bde65d9e-b17d-5746-8d29-8419363d0511"
		date = "2021-08-25"
		modified = "2023-12-05"
		reference = "https://www.huntress.com/blog/rapid-response-microsoft-exchange-servers-still-vulnerable-to-proxyshell-exploit"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_proxyshell.yar#L181-L196"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f2822a2b762c8e683c5e3a3f4a8232faa187b9a36182ea71e5286158b0e8115c"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$a1 = "<site name=" ascii
		$a2 = "<sectionGroup name=\"system.webServer\">" ascii
		$s1 = " physicalPath=\"C:\\ProgramData\\" ascii

	condition:
		filesize <500KB and all of ($a*) and 1 of ($s*)
}