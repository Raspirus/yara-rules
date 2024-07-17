rule SIGNATURE_BASE_Oilrig_Intelsecuritymanager : FILE
{
	meta:
		description = "Detects OilRig malware"
		author = "Eyal Sela"
		id = "4cccc0df-a225-5500-be55-f4ae346e066e"
		date = "2018-01-19"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_oilrig.yar#L235-L255"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "97debd5e74730e22133f29c89a0cf049862459c24d1b46634a973908040db3a7"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$one1 = "srvResesponded" ascii wide fullword
		$one2 = "InetlSecurityAssistManager" ascii wide fullword
		$one3 = "srvCheckresponded" ascii wide fullword
		$one4 = "IntelSecurityManager" ascii wide
		$one5 = "msoffice365cdn.com" ascii wide
		$one6 = "\\tmpCa.vbs" ascii wide
		$one7 = "AAZFinish" ascii wide fullword
		$one8 = "AAZUploaded" ascii wide fullword
		$one9 = "ABZFinish" ascii wide fullword
		$one10 = "\\tmpCa.vbs" ascii wide

	condition:
		filesize <300KB and any of them
}