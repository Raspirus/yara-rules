rule SIGNATURE_BASE_MAL_Burningumbrella_Sample_21 : FILE
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		author = "Florian Roth (Nextron Systems)"
		id = "2193e4b6-b71c-5031-8e43-fdd7177ad05c"
		date = "2018-05-04"
		modified = "2023-12-05"
		reference = "https://401trg.pw/burning-umbrella/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_winnti_burning_umbrella.yar#L357-L376"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "4fdb162575bd108bb35e5c8ed10f7cac7539a15349218222dbb82d8eae8ad4bb"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "4b7b9c2a9d5080ccc4e9934f2fd14b9d4e8f6f500889bf9750f1d672c8724438"

	strings:
		$s1 = "c:\\windows\\ime\\setup.exe" fullword ascii
		$s2 = "ws.run \"later.bat /start\",0Cet " fullword ascii
		$s3 = "del later.bat" fullword ascii
		$s4 = "mycrs.xls" fullword ascii
		$a1 = "-el -s2 \"-d%s\" \"-p%s\" \"-sp%s\"" fullword ascii
		$a2 = "<set ws=wscript.createobject(\"wscript.shell\")" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <500KB and 2 of them
}