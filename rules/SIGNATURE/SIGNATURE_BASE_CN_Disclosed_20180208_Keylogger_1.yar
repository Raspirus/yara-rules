import "pe"


rule SIGNATURE_BASE_CN_Disclosed_20180208_Keylogger_1 : FILE
{
	meta:
		description = "Detects malware from disclosed CN malware set"
		author = "Florian Roth (Nextron Systems)"
		id = "12eff9b6-1a65-5efc-b39c-88297bdae9c3"
		date = "2018-02-08"
		modified = "2023-12-05"
		reference = "https://www.virustotal.com/graph/#/selected/n120z79z208z189/drawer/graph-details"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_cn_campaign_njrat.yar#L105-L122"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "efba7004614c690e469082255cf7b5cb62cac5da2bfcc26e036e2eafcb5728f9"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "c492889e1d271a98e15264acbb21bfca9795466882520d55dc714c4899ed2fcf"

	strings:
		$x2 = "Process already elevated." fullword wide
		$x3 = "GetKeyloggErLogsResponse" fullword ascii
		$x4 = "get_encryptedPassword" fullword ascii
		$x5 = "DoDownloadAndExecute" fullword ascii
		$x6 = "GetKeyloggeRLogs" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and 2 of them
}