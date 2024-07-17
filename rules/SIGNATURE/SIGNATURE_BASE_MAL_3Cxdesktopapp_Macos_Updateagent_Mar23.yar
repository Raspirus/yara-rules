import "pe"


rule SIGNATURE_BASE_MAL_3Cxdesktopapp_Macos_Updateagent_Mar23 : FILE
{
	meta:
		description = "Detects 3CXDesktopApp MacOS UpdateAgent backdoor component"
		author = "Florian Roth (Nextron Systems)"
		id = "596eb6d0-f96f-5106-ae67-9372d238e4cf"
		date = "2023-03-30"
		modified = "2023-12-05"
		reference = "https://twitter.com/patrickwardle/status/1641692164303515653?s=20"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_mal_3cx_compromise_mar23.yar#L330-L354"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "9e9a5f8d86356796162cee881c843cde9eaedfb3"
		logic_hash = "0818a8f0b59a9baaefaa0b505f8261e0e0df283e79da8e95dc71e9afdca224ab"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$a1 = "/3CX Desktop App/.main_storage" ascii
		$x1 = ";3cx_auth_token_content=%s;__tutma=true"
		$s1 = "\"url\": \"https://"
		$s3 = "/dev/null"
		$s4 = "\"AccountName\": \""

	condition:
		uint16(0)==0xfeca and filesize <6MB and (1 of ($x*) or ($a1 and all of ($s*))) or all of them
}