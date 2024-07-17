import "pe"


import "pe"


import "pe"


rule ESET_IIS_Native_Module_PRIVATE : FILE
{
	meta:
		description = "Signature to match an IIS native module (clean or malicious)"
		author = "ESET Research"
		id = "e3bacdc8-fde1-5e83-ac94-79fc345e888d"
		date = "2021-08-04"
		modified = "2021-08-04"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/badiis/badiis.yar#L34-L92"
		license_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/LICENSE"
		logic_hash = "5a388dc3253df606e2648d1f9c018e6dde373bbddce66dba69b7aecdd95bac18"
		score = 75
		quality = 55
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$e1 = "This module subscribed to event"
		$e2 = "CHttpModule::OnBeginRequest"
		$e3 = "CHttpModule::OnPostBeginRequest"
		$e4 = "CHttpModule::OnAuthenticateRequest"
		$e5 = "CHttpModule::OnPostAuthenticateRequest"
		$e6 = "CHttpModule::OnAuthorizeRequest"
		$e7 = "CHttpModule::OnPostAuthorizeRequest"
		$e8 = "CHttpModule::OnResolveRequestCache"
		$e9 = "CHttpModule::OnPostResolveRequestCache"
		$e10 = "CHttpModule::OnMapRequestHandler"
		$e11 = "CHttpModule::OnPostMapRequestHandler"
		$e12 = "CHttpModule::OnAcquireRequestState"
		$e13 = "CHttpModule::OnPostAcquireRequestState"
		$e14 = "CHttpModule::OnPreExecuteRequestHandler"
		$e15 = "CHttpModule::OnPostPreExecuteRequestHandler"
		$e16 = "CHttpModule::OnExecuteRequestHandler"
		$e17 = "CHttpModule::OnPostExecuteRequestHandler"
		$e18 = "CHttpModule::OnReleaseRequestState"
		$e19 = "CHttpModule::OnPostReleaseRequestState"
		$e20 = "CHttpModule::OnUpdateRequestCache"
		$e21 = "CHttpModule::OnPostUpdateRequestCache"
		$e22 = "CHttpModule::OnLogRequest"
		$e23 = "CHttpModule::OnPostLogRequest"
		$e24 = "CHttpModule::OnEndRequest"
		$e25 = "CHttpModule::OnPostEndRequest"
		$e26 = "CHttpModule::OnSendResponse"
		$e27 = "CHttpModule::OnMapPath"
		$e28 = "CHttpModule::OnReadEntity"
		$e29 = "CHttpModule::OnCustomRequestNotification"
		$e30 = "CHttpModule::OnAsyncCompletion"
		$e31 = "CGlobalModule::OnGlobalStopListening"
		$e32 = "CGlobalModule::OnGlobalCacheCleanup"
		$e33 = "CGlobalModule::OnGlobalCacheOperation"
		$e34 = "CGlobalModule::OnGlobalHealthCheck"
		$e35 = "CGlobalModule::OnGlobalConfigurationChange"
		$e36 = "CGlobalModule::OnGlobalFileChange"
		$e37 = "CGlobalModule::OnGlobalApplicationStart"
		$e38 = "CGlobalModule::OnGlobalApplicationResolveModules"
		$e39 = "CGlobalModule::OnGlobalApplicationStop"
		$e40 = "CGlobalModule::OnGlobalRSCAQuery"
		$e41 = "CGlobalModule::OnGlobalTraceEvent"
		$e42 = "CGlobalModule::OnGlobalCustomNotification"
		$e43 = "CGlobalModule::OnGlobalThreadCleanup"
		$e44 = "CGlobalModule::OnGlobalApplicationPreload"

	condition:
		uint16(0)==0x5A4D and pe.exports("RegisterModule") and any of ($e*)
}