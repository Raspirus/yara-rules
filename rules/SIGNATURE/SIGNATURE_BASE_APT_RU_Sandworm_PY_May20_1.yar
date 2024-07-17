
rule SIGNATURE_BASE_APT_RU_Sandworm_PY_May20_1 : FILE
{
	meta:
		description = "Detects Sandworm Python loader"
		author = "Florian Roth (Nextron Systems)"
		id = "a392d800-1fe8-5ae9-b813-e1dfcedecda6"
		date = "2020-05-28"
		modified = "2023-12-05"
		reference = "https://twitter.com/billyleonard/status/1266054881225236482"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_sandworm_exim_expl.yar#L131-L148"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "2ccc4c7fc75c04cbcab34904de2e7ab055a15c1017ec0f8d01b06454f4395047"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "c025008463fdbf44b2f845f2d82702805d931771aea4b506573b83c8f58bccca"

	strings:
		$x1 = "o.addheaders=[('User-Agent','Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko')]" ascii fullword
		$s1 = "exec(o.open('http://" ascii
		$s2 = "__import__({2:'urllib2',3:'urllib.request'}"

	condition:
		uint16(0)==0x6d69 and filesize <1KB and 1 of ($x*) or 2 of them
}