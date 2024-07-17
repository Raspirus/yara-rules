
rule SIGNATURE_BASE_EXP_Libre_Office_CVE_2018_16858 : CVE_2018_16858 FILE
{
	meta:
		description = "RCE in Libre Office with crafted ODT file (CVE-2018-16858)"
		author = "John Lambert @JohnLaTwC / modified by Florian Roth"
		id = "17a0a569-27bf-57ab-937e-8943442ae604"
		date = "2019-02-01"
		modified = "2023-12-05"
		reference = "https://insert-script.blogspot.com/2019/02/libreoffice-cve-2018-16858-remote-code.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/exploit_cve_2018_16858.yar#L1-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "95a02b70c117947ff989e3e00868c2185142df9be751a3fefe21f18fa16a1a6f"
		logic_hash = "6dd34350f24945ba5a594acae96dc00bb200841a645443a70a59006cea1db949"
		score = 75
		quality = 83
		tags = "CVE-2018-16858, FILE"

	strings:
		$s1 = "xlink:href=\"vnd.sun.star.script:" ascii nocase
		$s2 = ".py$tempfilepager" ascii nocase
		$tag = {3c 6f 66 66 69 63 65 3a 64 6f 63 }

	condition:
		uint32be(0)==0x3c3f786d and $tag in (0..0100) and all of ($s*)
}