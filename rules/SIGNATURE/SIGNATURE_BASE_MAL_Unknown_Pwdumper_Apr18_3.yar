rule SIGNATURE_BASE_MAL_Unknown_Pwdumper_Apr18_3 : FILE
{
	meta:
		description = "Detects sample from unknown sample set - IL origin"
		author = "Florian Roth (Nextron Systems)"
		id = "2431d562-dcd8-5d21-8406-7d2567b6eca9"
		date = "2018-04-06"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-hacktools.yar#L4177-L4196"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "bf0dff02bdfa239336b2bc865f2a9aed6d20cafb059caa87a60aa30269dd94b5"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "d435e7b6f040a186efeadb87dd6d9a14e038921dc8b8658026a90ae94b4c8b05"
		hash2 = "8c35c71838f34f7f7a40bf06e1d2e14d58d9106e6d4e6f6e9af732511a126276"

	strings:
		$s1 = "loaderx86.dll" fullword ascii
		$s2 = "tcpsvcs.exe" fullword wide
		$s3 = "%Program Files, Common FOLDER%" fullword wide
		$s4 = "%AllUsers, ApplicationData FOLDER%" fullword wide
		$s5 = "loaderx86" fullword ascii
		$s6 = "TNtDllHook$" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and all of them
}