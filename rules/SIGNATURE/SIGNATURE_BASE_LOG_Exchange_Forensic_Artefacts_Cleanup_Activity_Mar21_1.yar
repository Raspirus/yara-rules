rule SIGNATURE_BASE_LOG_Exchange_Forensic_Artefacts_Cleanup_Activity_Mar21_1 : LOG
{
	meta:
		description = "Detects forensic artefacts showing cleanup activity found in HAFNIUM intrusions exploiting"
		author = "Florian Roth (Nextron Systems)"
		id = "95b19544-147b-5496-b717-669cbc488179"
		date = "2021-03-08"
		modified = "2023-12-05"
		reference = "https://twitter.com/jdferrell3/status/1368626281970024448"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_hafnium_log_sigs.yar#L48-L65"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "12e5b76dafcae13f1eb21913ae0bde233152fd8b9d29f073893418ac9f742de3"
		score = 70
		quality = 85
		tags = "LOG"

	strings:
		$x1 = "cmd.exe /c cd /d C:/inetpub/wwwroot/aspnet_client" ascii wide
		$x2 = "cmd.exe /c cd /d C:\\inetpub\\wwwroot\\aspnet_client" ascii wide
		$s1 = "aspnet_client&del '"
		$s2 = "aspnet_client&attrib +h +s +r "
		$s3 = "&echo [S]"

	condition:
		1 of ($x*) or 2 of them
}