rule SIGNATURE_BASE_APT_NK_AR18_165A_1 : FILE
{
	meta:
		description = "Detects APT malware from AR18-165A report by US CERT"
		author = "Florian Roth (Nextron Systems)"
		id = "45f5205d-7f69-5646-aef8-f95d139f9720"
		date = "2018-06-15"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/analysis-reports/AR18-165A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ar18_165a.yar#L62-L76"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7b87c537c9ff38329a5e1e39d5ad1d6cef724c580f246721443eab603534b29d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "089e49de61701004a5eff6de65476ed9c7632b6020c2c0f38bb5761bca897359"

	strings:
		$s1 = "netsh.exe advfirewall firewall add rule name=\"PortOpenning\" dir=in protocol=tcp localport=%d action=allow enable=yes" fullword wide
		$s2 = "netsh.exe firewall add portopening TCP %d \"PortOpenning\" enable" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and 1 of them
}