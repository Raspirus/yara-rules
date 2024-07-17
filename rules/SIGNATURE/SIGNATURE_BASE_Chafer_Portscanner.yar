rule SIGNATURE_BASE_Chafer_Portscanner : FILE
{
	meta:
		description = "Detects Custom Portscanner used by Oilrig"
		author = "Markus Neis"
		id = "8db934c3-fb0d-5c87-9096-1ee8fb16f9a5"
		date = "2018-03-22"
		modified = "2023-12-05"
		reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_oilrig_chafer_mar18.yar#L45-L59"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "6e0475a5c0fc8155359376113f88f3de080968388bd3ea60664a063540688faf"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "88274a68a6e07bdc53171641e7349d6d0c71670bd347f11dcc83306fe06656e9"

	strings:
		$x1 = "C:\\Users\\RS01204N\\Documents\\" ascii
		$x2 = "PortScanner /ip:google.com  /port:80 /t:500 /tout:2" fullword ascii
		$x3 = "open ports of host/hosts" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and 1 of them
}