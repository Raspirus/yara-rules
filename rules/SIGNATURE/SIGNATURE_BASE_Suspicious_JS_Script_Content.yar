
rule SIGNATURE_BASE_Suspicious_JS_Script_Content : FILE
{
	meta:
		description = "Detects suspicious statements in JavaScript files"
		author = "Florian Roth (Nextron Systems)"
		id = "6a547aa5-c58c-5559-9d3f-3f0d541eafd4"
		date = "2017-12-02"
		modified = "2023-12-05"
		reference = "Research on Leviathan https://goo.gl/MZ7dRg"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_mal_scripts.yar#L95-L112"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "1dbc1a266d710a70a77c81d5b872d0d324423250a9f34455faef53ac4c41b5f2"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "fc0fad39b461eb1cfc6be57932993fcea94fca650564271d1b74dd850c81602f"

	strings:
		$x1 = "new ActiveXObject('WScript.Shell')).Run('cmd /c " ascii
		$x2 = ".Run('regsvr32 /s /u /i:" ascii
		$x3 = "new ActiveXObject('WScript.Shell')).Run('regsvr32 /s" fullword ascii
		$x4 = "args='/s /u /i:" ascii

	condition:
		( filesize <10KB and 1 of them )
}