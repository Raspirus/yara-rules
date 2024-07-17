rule SIGNATURE_BASE_CN_Disclosed_20180208_Mal5 : FILE
{
	meta:
		description = "Detects malware from disclosed CN malware set"
		author = "Florian Roth (Nextron Systems)"
		id = "b1933610-9e6d-5eed-ba30-ccdd0d3a6124"
		date = "2018-02-08"
		modified = "2023-12-05"
		reference = "https://www.virustotal.com/graph/#/selected/n120z79z208z189/drawer/graph-details"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_cn_campaign_njrat.yar#L140-L160"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "971276d5033477a08a1ec037cff9735667c2b4f7d9d4a7bcd88f2b1d8c348d4f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "24c05cd8a1175fbd9aca315ec67fb621448d96bd186e8d5e98cb4f3a19482af4"
		hash2 = "05696db46144dab3355dcefe0408f906a6d43fced04cb68334df31c6dfd12720"

	strings:
		$s1 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
		$s2 = "Server.exe" fullword ascii
		$s3 = "System.Windows.Forms.Form" fullword ascii
		$s4 = "Stub.Resources.resources" fullword ascii
		$s5 = "My.Computer" fullword ascii
		$s6 = "MyTemplate" fullword ascii
		$s7 = "Stub.My.Resources" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and all of them
}