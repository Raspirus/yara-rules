import "pe"


rule SIGNATURE_BASE_SUSP_Screenconnect_User_Poc_Com_Used_Feb24 : FILE
{
	meta:
		description = "Detects suspicious ScreenConnect user with poc.com email address, which is a sign of exploitation of the ConnectWise ScreenConnect (versions prior to 23.9.8) vulnerability with the POC released by WatchTower and the account was already used yet to login"
		author = "Florian Roth"
		id = "91990558-f145-5968-9722-b6815f6ad8d5"
		date = "2024-02-23"
		modified = "2024-04-24"
		reference = "https://github.com/watchtowrlabs/connectwise-screenconnect_auth-bypass-add-user-poc/blob/45e5b2f699a4d8f2d59ec3fc79a2e3c99db71882/watchtowr-vs-ConnectWise_2024-02-21.py#L53"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_connectwise_screenconnect_vuln_feb24.yar#L40-L60"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "50967a07a9789f20ccbc882c3b9e3142f0c28068c0a58b9d8927d725d02bf289"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$a1 = "<Users xmlns:xsi="
		$a2 = "<CreationDate>"
		$s1 = "@poc.com</Email>"
		$f1 = "<LastLoginDate>0001"

	condition:
		filesize <200KB and all of ($a*) and $s1 and not 1 of ($f*)
}