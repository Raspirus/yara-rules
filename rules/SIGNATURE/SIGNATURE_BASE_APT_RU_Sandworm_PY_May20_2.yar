rule SIGNATURE_BASE_APT_RU_Sandworm_PY_May20_2 : FILE
{
	meta:
		description = "Detects Sandworm Python loader"
		author = "Florian Roth (Nextron Systems)"
		id = "5b32ad64-d959-5632-a03c-17aa055b213f"
		date = "2020-05-28"
		modified = "2023-12-05"
		reference = "https://twitter.com/billyleonard/status/1266054881225236482"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_sandworm_exim_expl.yar#L150-L167"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "5fb61a9cef64ecf97adc78bf67db667cfd9e5e6f3e03f1bba8f3cdbf6c257520"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "abfa83cf54db8fa548942acd845b4f34acc94c46d4e1fb5ce7e97cc0c6596676"

	strings:
		$x1 = "import sys;import re, subprocess;cmd" ascii fullword
		$x2 = "UA='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';server='http"
		$x3 = "';t='/admin/get.php';req" ascii
		$x4 = "ps -ef | grep Little\\ Snitch | grep " ascii fullword

	condition:
		uint16(0)==0x6d69 and filesize <2KB and 1 of them
}