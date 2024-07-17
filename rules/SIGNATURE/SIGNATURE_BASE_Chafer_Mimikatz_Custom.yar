rule SIGNATURE_BASE_Chafer_Mimikatz_Custom : FILE
{
	meta:
		description = "Detects Custom Mimikatz Version"
		author = "Florian Roth (Nextron Systems) / Markus Neis"
		id = "80f751c3-d7ca-5ff6-a905-38650e1c4ec5"
		date = "2018-03-22"
		modified = "2023-12-05"
		reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_oilrig_chafer_mar18.yar#L11-L23"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "d3b74be6d221592fb867bd9589f5e4b246a093bd276efa3515d9e948a38eda48"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "9709afeb76532566ee3029ecffc76df970a60813bcac863080cc952ad512b023"

	strings:
		$x1 = "C:\\Users\\win7p\\Documents\\mi-back\\" ascii

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and 1 of them
}