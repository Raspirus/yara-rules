
rule SIGNATURE_BASE_APT_IIS_Config_Proxyshell_Artifacts : FILE
{
	meta:
		description = "Detects virtual directory configured in IIS pointing to a ProgramData folder (as found in attacks against Exchange servers in August 2021)"
		author = "Florian Roth (Nextron Systems)"
		id = "21888fc0-82c6-555a-9320-9cbb8332a843"
		date = "2021-08-25"
		modified = "2023-12-05"
		reference = "https://www.huntress.com/blog/rapid-response-microsoft-exchange-servers-still-vulnerable-to-proxyshell-exploit"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_proxyshell.yar#L83-L106"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a4557694629448d258b8b2fefc278e059217560e7a0ec3279863a16fb9b3989c"
		score = 90
		quality = 85
		tags = "FILE"

	strings:
		$a1 = "<site name=" ascii
		$a2 = "<sectionGroup name=\"system.webServer\">" ascii
		$sa1 = " physicalPath=\"C:\\ProgramData\\COM" ascii
		$sa2 = " physicalPath=\"C:\\ProgramData\\WHO" ascii
		$sa3 = " physicalPath=\"C:\\ProgramData\\ZING" ascii
		$sa4 = " physicalPath=\"C:\\ProgramData\\ZOO" ascii
		$sa5 = " physicalPath=\"C:\\ProgramData\\XYZ" ascii
		$sa6 = " physicalPath=\"C:\\ProgramData\\AUX" ascii
		$sa7 = " physicalPath=\"C:\\ProgramData\\CON\\" ascii
		$sb1 = " physicalPath=\"C:\\Users\\All Users\\" ascii

	condition:
		filesize <500KB and all of ($a*) and 1 of ($s*)
}