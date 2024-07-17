rule SIGNATURE_BASE_SUSP_OBFUSC_JS_Sept21_2 : FILE
{
	meta:
		description = "Detects JavaScript obfuscation as used in MalDocs by FIN7 group"
		author = "Florian Roth (Nextron Systems)"
		id = "5ab9cd60-077c-5066-bd2f-8da261aae1e0"
		date = "2021-09-07"
		modified = "2023-12-05"
		reference = "https://www.anomali.com/blog/cybercrime-group-fin7-using-windows-11-alpha-themed-docs-to-drop-javascript-backdoor"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_fin7.yar#L303-L323"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "235ff8fe5c033fd90d77ecf9ce80b59be7bf6ae5a2863a1c9365d8b125a7ff3f"
		score = 65
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "=new RegExp(String.fromCharCode(" ascii
		$s2 = ".charCodeAt(" ascii
		$s3 = ".substr(0, " ascii
		$s4 = "var shell = new ActiveXObject(" ascii
		$s5 = "= new Date().getUTCMilliseconds();" ascii
		$s6 = ".deleteFile(WScript.ScriptFullName);" ascii

	condition:
		filesize <6000KB and (4 of them )
}