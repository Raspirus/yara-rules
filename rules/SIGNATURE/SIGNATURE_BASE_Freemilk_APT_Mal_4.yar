rule SIGNATURE_BASE_Freemilk_APT_Mal_4 : FILE
{
	meta:
		description = "Detects malware from FreeMilk campaign"
		author = "Florian Roth (Nextron Systems)"
		id = "44f919f7-8eda-5e70-88d5-9e81a761192c"
		date = "2017-10-05"
		modified = "2023-12-05"
		reference = "https://researchcenter.paloaltonetworks.com/2017/10/unit42-freemilk-highly-targeted-spear-phishing-campaign/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_freemilk.yar#L80-L104"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "deedb1da7e3421cd300fceea354a690e22005bab16eb0cc20b46f912393b637d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "99c1b4887d96cb94f32b280c1039b3a7e39ad996859ffa6dd011cf3cca4f1ba5"

	strings:
		$x1 = "base64Encoded=\"TVqQAAMAAAAE" ascii
		$s1 = "SOFTWARE\\Clients\\StartMenuInternet\\firefox.exe\\shell\\open\\command" fullword wide
		$s2 = "'Wscript.echo \"Base64 encoded: \" + base64Encoded" fullword ascii
		$s3 = "\\Google\\Chrome\\User Data\\Default\\Login Data" ascii
		$s4 = "outFile=sysDir&\"\\rundll32.exe\"" fullword ascii
		$s5 = "set shell = WScript.CreateObject(\"WScript.Shell\")" fullword ascii
		$s6 = "command =outFile &\" sysupdate\"" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and ((pe.exports("getUpdate") and pe.number_of_exports==1) or 1 of ($x*) or 3 of them )
}