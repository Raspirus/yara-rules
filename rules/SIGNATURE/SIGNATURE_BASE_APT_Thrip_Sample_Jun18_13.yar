import "pe"


rule SIGNATURE_BASE_APT_Thrip_Sample_Jun18_13 : FILE
{
	meta:
		description = "Detects sample found in Thrip report by Symantec "
		author = "Florian Roth (Nextron Systems)"
		id = "e6aec6f3-2024-5fb2-b37a-77a182684d32"
		date = "2018-06-21"
		modified = "2023-12-05"
		reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_thrip.yar#L236-L254"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "3c319a3ca78687cd2af77d97b4b4a8e72dadd812bf3da2145a23df278c3aa9a2"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "780620521c92aab3d592b3dc149cbf58751ea285cfdaa50510002b441796b312"

	strings:
		$s1 = "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko" fullword ascii
		$s2 = "<member><name>password</name>" fullword ascii
		$s3 = "<value><string>qqtorspy</string></value>" fullword ascii
		$s4 = "SOFTWARE\\QKitTORSPY" fullword wide
		$s5 = "ipecho.net" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <500KB and (pe.imphash()=="3dfad33b2fb66c083c99dc10341908b7" or 4 of them )
}