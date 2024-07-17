
rule SIGNATURE_BASE_Irontiger_Nbddos_Gh0Stvariant_Dropper : FILE
{
	meta:
		description = "Iron Tiger Malware - NBDDos Gh0stvariant Dropper"
		author = "Cyber Safety Solutions, Trend Micro"
		id = "3610b9e3-45f8-5a8d-8977-817160009818"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "http://goo.gl/T5fSJC"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_irontiger_trendmicro.yar#L154-L169"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e877c52d5cb0067388e9a138f48dcf7d3bd6d7d491eea6acffb2527ba0a906c7"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$str1 = "This service can't be stoped." wide ascii
		$str2 = "Provides support for media palyer" wide ascii
		$str4 = "CreaetProcess Error" wide ascii
		$bla1 = "Kill You" wide ascii
		$bla2 = "%4.2f GB" wide ascii

	condition:
		uint16(0)==0x5a4d and (( any of ($str*)) or ( all of ($bla*)))
}