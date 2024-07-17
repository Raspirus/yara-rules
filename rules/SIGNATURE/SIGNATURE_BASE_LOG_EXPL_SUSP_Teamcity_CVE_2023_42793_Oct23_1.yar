rule SIGNATURE_BASE_LOG_EXPL_SUSP_Teamcity_CVE_2023_42793_Oct23_1 : CVE_2023_42793
{
	meta:
		description = "Detects log entries that could indicate a successful exploitation of CVE-2023-42793 on TeamCity servers"
		author = "Florian Roth"
		id = "81c04863-72aa-5515-889e-3ef718360cac"
		date = "2023-10-02"
		modified = "2023-12-05"
		reference = "https://attackerkb.com/topics/1XEEEkGHzt/cve-2023-42793/rapid7-analysis"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_teamcity_2023_42793.yar#L2-L18"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "3b6c8e3e3ff91563899ca94904a56460cd702a3e58e0aacf1c3acb506ec3f959"
		score = 70
		quality = 85
		tags = "CVE-2023-42793"

	strings:
		$sa1 = "File edited: "
		$sa2 = "\\TeamCity\\config\\internal.properties by user with id="
		$sb1 = "s.buildServer.ACTIVITIES.AUDIT - server_file_change: File "
		$sb2 = "\\TeamCity\\config\\internal.properties was modified by \"user with id"

	condition:
		all of ($sa*) or all of ($sb*)
}