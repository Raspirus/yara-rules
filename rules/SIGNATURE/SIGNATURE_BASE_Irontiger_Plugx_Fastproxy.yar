
rule SIGNATURE_BASE_Irontiger_Plugx_Fastproxy : FILE
{
	meta:
		description = "Iron Tiger Malware - PlugX FastProxy"
		author = "Cyber Safety Solutions, Trend Micro"
		id = "14e05823-6288-5f02-8060-add51084c446"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "http://goo.gl/T5fSJC"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_irontiger_trendmicro.yar#L187-L203"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "6659595f65b445d2bd69b13b8d01c2dd78b5c055fa39f810a61646d9408df2ff"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$str1 = "SAFEPROXY HTServerTimer Quit!" wide ascii
		$str2 = "Useage: %s pid" wide ascii
		$str3 = "%s PORT[%d] TO PORT[%d] SUCCESS!" wide ascii
		$str4 = "p0: port for listener" wide ascii
		$str5 = "\\users\\whg\\desktop\\plug\\" wide ascii
		$str6 = "[+Y] cwnd : %3d, fligth:" wide ascii

	condition:
		uint16(0)==0x5a4d and ( any of ($str*))
}