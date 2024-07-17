rule SIGNATURE_BASE_Freeenki_Infostealer_Nov17 : FILE
{
	meta:
		description = "Detects Freenki infostealer malware"
		author = "Florian Roth (Nextron Systems)"
		id = "01365093-e40a-524a-8a13-217742542f1e"
		date = "2017-11-28"
		modified = "2023-01-06"
		reference = "http://blog.talosintelligence.com/2017/11/ROKRAT-Reloaded.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_rokrat.yar#L63-L92"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e823ef5506b2fdf30a6ff9bdf6eee552b767b66a6c007a30618fc212d598b540"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "99c1b4887d96cb94f32b280c1039b3a7e39ad996859ffa6dd011cf3cca4f1ba5"

	strings:
		$x1 = "base64Encoded=\"TVqQAAMAAAAEAAAA" ascii
		$x2 = "command =outFile &\" sysupdate\"" fullword ascii
		$x3 = "outFile=sysDir&\"\\rundll32.exe\"" fullword ascii
		$s1 = "SOFTWARE\\Clients\\StartMenuInternet\\firefox.exe\\shell\\open\\command" fullword wide
		$s2 = "c:\\TEMP\\CrashReports\\" ascii
		$s3 = "objShell.run command, 0, True" fullword ascii
		$s4 = "sysDir = shell.ExpandEnvironmentStrings(\"%windir%\")" fullword ascii
		$s5 = "'Wscript.echo \"Base64 encoded: \" + base64Encoded" fullword ascii
		$s6 = "set shell = WScript.CreateObject(\"WScript.Shell\")" fullword ascii
		$a1 = "\\Google\\Chrome\\User Data\\Default\\Login Data" ascii
		$a2 = "SELECT username_value, password_value, signon_realm FROM logins" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and (1 of ($x*) or 3 of them or all of ($a*))
}