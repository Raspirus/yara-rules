
rule SIGNATURE_BASE_APT_MAL_BKA_Goldenspy_Aug20_1 : FILE
{
	meta:
		description = "Detects variants of GoldenSpy Malware"
		author = "BKA"
		id = "4f47087e-6e68-53ff-9446-72a1751da359"
		date = "2020-08-21"
		modified = "2023-12-05"
		reference = "https://www.bka.de/SharedDocs/Kurzmeldungen/DE/Warnhinweise/200821_Cyberspionage.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_goldenspy.yar#L1-L19"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ba81a2b081842aaf06bbf623640a87946894df83fd0d7b7149c48afa8ed0a081"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$str01 = {c78510ffffff00000000 c78514ffffff0f000000 c68500ffffff00 c78528ffffff00000000 c7852cffffff0f000000 c68518ffffff00 c78540ffffff00000000 c78544ffffff0f000000 c68530ffffff00 c645fc14 80bd04feffff00}
		$str02 = "Ryeol HTTP Client Class" ascii
		$str03 = "----RYEOL-FB3B405B7EAE495aB0C0295C54D4E096-" ascii
		$str04 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\fwkp.exe" ascii
		$str05 = "svmm" ascii
		$str06 = "PROTOCOL_" ascii
		$str07 = "softList" ascii
		$str08 = "excuteExe" ascii

	condition:
		uint16(0)==0x5A4D and 5 of ($str*)
}