
rule SIGNATURE_BASE_EXT_MAL_JS_Socgholish_Mar21_1 : JS SOCGHOLISH FILE
{
	meta:
		description = "Triggers on SocGholish JS files"
		author = "Nils Kuhnert"
		id = "3ed7d2da-569b-5851-a821-4a3cda3e13ce"
		date = "2021-03-29"
		modified = "2023-01-02"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_socgholish.yar#L25-L51"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "7ccbdcde5a9b30f8b2b866a5ca173063dec7bc92034e7cf10e3eebff017f3c23"
		hash = "f6d738baea6802cbbb3ae63b39bf65fbd641a1f0d2f0c819a8c56f677b97bed1"
		hash = "c7372ffaf831ad963c0a9348beeaadb5e814ceeb878a0cc7709473343d63a51c"
		logic_hash = "08218ae952577a6ac936de875236cdc3ae32e3aaccd2196b7f43e80d7e748584"
		score = 75
		quality = 85
		tags = "JS, SOCGHOLISH, FILE"

	strings:
		$s1 = "new ActiveXObject('Scripting.FileSystemObject');" ascii
		$s2 = "['DeleteFile']" ascii
		$s3 = "['WScript']['ScriptFullName']" ascii
		$s4 = "['WScript']['Sleep'](1000)" ascii
		$s5 = "new ActiveXObject('MSXML2.XMLHTTP')" ascii
		$s6 = "this['eval']" ascii
		$s7 = "String['fromCharCode']"
		$s8 = "2), 16)," ascii
		$s9 = "= 103," ascii
		$s10 = "'00000000'" ascii

	condition:
		filesize >3KB and filesize <5KB and 8 of ($s*)
}