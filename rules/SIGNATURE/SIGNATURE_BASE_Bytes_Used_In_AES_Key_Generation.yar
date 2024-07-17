rule SIGNATURE_BASE_Bytes_Used_In_AES_Key_Generation : FILE
{
	meta:
		description = "Detects Backdoor.goodor"
		author = "NCSC"
		id = "26a549dd-cbd2-5abc-8d9d-5ea354d0ece8"
		date = "2018-04-06"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ncsc_report_04_2018.yar#L9-L22"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "b5278301da06450fe4442a25dda2d83d21485be63598642573f59c59e980ad46"
		logic_hash = "221f5ea0a0224a96588912e7ddfbafd20b0b10c119395ca14d1138c284d7b79e"
		score = 75
		quality = 83
		tags = "FILE"

	strings:
		$a1 = {35 34 36 35 4B 4A 55 54 5E 49 55 5F 29 7B 68 36 35 67 34 36 64 66 35 68}

	condition:
		uint16(0)==0x5a4d and filesize <5000KB and all of ($a*)
}