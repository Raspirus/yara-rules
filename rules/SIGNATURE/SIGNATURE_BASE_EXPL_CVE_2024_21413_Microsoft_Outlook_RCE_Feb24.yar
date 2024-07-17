
rule SIGNATURE_BASE_EXPL_CVE_2024_21413_Microsoft_Outlook_RCE_Feb24 : CVE_2024_21413 FILE
{
	meta:
		description = "Detects emails that contain signs of a method to exploit CVE-2024-21413 in Microsoft Outlook"
		author = "X__Junior, Florian Roth"
		id = "4512ca7b-0755-565e-84f1-596552949aa5"
		date = "2024-02-17"
		modified = "2024-02-19"
		reference = "https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_outlook_cve_2024_21413.yar#L2-L20"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "06cfafe0b92949e493dca6d54f671d0607242d97341144b69f563a0cc24dc6a1"
		score = 75
		quality = 85
		tags = "CVE-2024-21413, FILE"

	strings:
		$a1 = "Subject: "
		$a2 = "Received: "
		$xr1 = /file:\/\/\/\\\\[^"']{6,600}\.(docx|txt|pdf|xlsx|pptx|odt|etc|jpg|png|gif|bmp|tiff|svg|mp4|avi|mov|wmv|flv|mkv|mp3|wav|aac|flac|ogg|wma|exe|msi|bat|cmd|ps1|zip|rar|7z|targz|iso|dll|sys|ini|cfg|reg|html|css|java|py|c|cpp|db|sql|mdb|accdb|sqlite|eml|pst|ost|mbox|htm|php|asp|jsp|xml|ttf|otf|woff|woff2|rtf|chm|hta|js|lnk|vbe|vbs|wsf|xls|xlsm|xltm|xlt|doc|docm|dot|dotm)!/

	condition:
		filesize <1000KB and all of ($a*) and 1 of ($xr*)
}