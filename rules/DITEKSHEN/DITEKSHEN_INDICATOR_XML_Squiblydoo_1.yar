rule DITEKSHEN_INDICATOR_XML_Squiblydoo_1 : FILE
{
	meta:
		description = "detects Squiblydoo variants extracted from exploit RTF documents."
		author = "ditekSHen"
		id = "cac326ab-cc31-59c1-bd12-285db1675695"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_office.yar#L583-L597"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "b52ebd76dd4e60f6bd5cb19fed3a72b6aeb90dea95f0d1be61dcfff39ea674ae"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$slt = "<scriptlet" ascii
		$ws1 = "CreateObject(\"WScript\" & \".Shell\")" ascii
		$ws2 = "CreateObject(\"WScript.Shell\")" ascii
		$ws3 = "ActivexObject(\"WScript.Shell\")" ascii
		$r1 = "[\"run\"]" nocase ascii
		$r2 = ".run \"cmd" nocase ascii
		$r3 = ".run chr(" nocase ascii

	condition:
		( uint32(0)==0x4d583f3c or uint32(0)==0x6d783f3c) and $slt and 1 of ($ws*) and 1 of ($r*)
}