rule SIGNATURE_BASE_MAL_Muddywater_Droppedtask_Jun18_1 : FILE
{
	meta:
		description = "Detects a dropped Windows task as used by MudyWater in June 2018"
		author = "Florian Roth (Nextron Systems)"
		id = "d9ef379d-161f-59f1-873e-3af12b24b76b"
		date = "2018-06-12"
		modified = "2023-12-05"
		reference = "https://app.any.run/tasks/719c94eb-0a00-47cc-b583-ad4f9e25ebdb"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_muddywater.yar#L48-L66"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "776ae1adab223ae258d1c1c0c501e177dafe196964a2ede31789a7caa8495b2d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "7ecc2e1817f655ece2bde39b7d6633f4f586093047ec5697a1fab6adc7e1da54"

	strings:
		$x1 = "%11%\\scrobj.dll,NI,c:" wide
		$s1 = "AppAct = \"SOFTWARE\\Microsoft\\Connection Manager\"" fullword wide
		$s2 = "[DefenderService]" fullword wide
		$s3 = "UnRegisterOCXs=EventManager" fullword wide
		$s4 = "ShortSvcName=\" \"" fullword wide

	condition:
		uint16(0)==0xfeff and filesize <1KB and (1 of ($x*) or 3 of them )
}