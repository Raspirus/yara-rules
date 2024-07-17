rule SIGNATURE_BASE_SUSP_Screenconnect_User_Poc_Com_Unused_Feb24 : FILE
{
	meta:
		description = "Detects suspicious ScreenConnect user with poc.com email address, which is a sign of exploitation of the ConnectWise ScreenConnect (versions prior to 23.9.8) vulnerability with the POC released by WatchTower and the account wasn't actually used yet to login"
		author = "Florian Roth"
		id = "c57e6c6a-298f-5ff3-b76a-03127ff88699"
		date = "2024-02-23"
		modified = "2024-04-24"
		reference = "https://github.com/watchtowrlabs/connectwise-screenconnect_auth-bypass-add-user-poc/blob/45e5b2f699a4d8f2d59ec3fc79a2e3c99db71882/watchtowr-vs-ConnectWise_2024-02-21.py#L53"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_connectwise_screenconnect_vuln_feb24.yar#L20-L38"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "2433ad11ca1d9f970eb3c536a13f07e808c2a0b8b0dd625dffbe4947268ab8f5"
		score = 65
		quality = 85
		tags = "FILE"

	strings:
		$a1 = "<Users xmlns:xsi="
		$a2 = "<CreationDate>"
		$s1 = "@poc.com</Email>"
		$s2 = "<LastLoginDate>0001"

	condition:
		filesize <200KB and all of ($a*) and all of ($s*)
}