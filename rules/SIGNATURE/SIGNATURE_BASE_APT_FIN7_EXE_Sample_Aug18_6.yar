rule SIGNATURE_BASE_APT_FIN7_EXE_Sample_Aug18_6 : FILE
{
	meta:
		description = "Detects sample from FIN7 report in August 2018"
		author = "Florian Roth (Nextron Systems)"
		id = "2b2e6b74-5d71-5656-8faf-37c94607d93e"
		date = "2018-08-01"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_fin7.yar#L175-L198"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "33db8e61b6220d9e16191228573d3d375cce9528241dcf1ad74d641f0959f03b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "1439d301d931c8c4b00717b9057b23f0eb50049916a48773b17397135194424a"

	strings:
		$s1 = "coreServiceShell.exe" fullword ascii
		$s2 = "PtSessionAgent.exe" fullword ascii
		$s3 = "TiniMetI.exe" fullword ascii
		$s4 = "PwmSvc.exe" fullword ascii
		$s5 = "uiSeAgnt.exe" fullword ascii
		$s7 = "LHOST:" fullword ascii
		$s8 = "TRANSPORT:" fullword ascii
		$s9 = "LPORT:" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <20KB and (pe.exports("TiniStart") or 4 of them )
}