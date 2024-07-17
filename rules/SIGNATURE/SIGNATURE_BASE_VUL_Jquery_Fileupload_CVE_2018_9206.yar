rule SIGNATURE_BASE_VUL_Jquery_Fileupload_CVE_2018_9206 : CVE_2018_9206
{
	meta:
		description = "Detects JQuery File Upload vulnerability CVE-2018-9206"
		author = "Florian Roth (Nextron Systems)"
		id = "20bac44c-0e5a-5561-9fd8-a71cd2d8590a"
		date = "2018-10-19"
		modified = "2023-12-05"
		reference = "https://blogs.akamai.com/sitr/2018/10/having-the-security-rug-pulled-out-from-under-you.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/vul_jquery_fileupload_cve_2018_9206.yar#L1-L16"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ef7cc13130c60ece346802cb6efec96065f84407fb84b89703628fdf32c0ee53"
		score = 75
		quality = 85
		tags = "CVE-2018-9206"

	strings:
		$s1 = "error_reporting(E_ALL | E_STRICT);" fullword ascii
		$s2 = "require('UploadHandler.php');" fullword ascii
		$s3 = "$upload_handler = new UploadHandler();" fullword ascii

	condition:
		all of them
}