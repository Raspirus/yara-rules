rule SIGNATURE_BASE_MAL_LNX_Camarodragon_Horseshell_Oct23 : FILE
{
	meta:
		description = "Detects CamaroDragon's HorseShell implant for routers"
		author = "Florian Roth"
		id = "9e54745f-146f-50a6-b30f-53aaaa6907b5"
		date = "2023-10-06"
		modified = "2023-12-05"
		reference = "https://research.checkpoint.com/2023/the-dragon-who-sold-his-camaro-analyzing-custom-router-implant/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_camaro_dragon_oct23.yar#L27-L56"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "73adaa286b345cffd35e6ba017b3204d8818dcaeea8a48ca93959566461ac3ca"
		score = 85
		quality = 85
		tags = "FILE"
		hash1 = "998788472cb1502c03675a15a9f09b12f3877a5aeb687f891458a414b8e0d66c"

	strings:
		$x1 = "echo \"start shell '%s' failed!\" > .remote_shell.log" ascii fullword
		$x2 = "*****recv NET_REQ_HORSE_SHELL REQ_CONNECT_PORT*****" ascii fullword
		$s1 = "m.cremessage.com" ascii fullword
		$s2 = "POST http://%s/index.php HTTP/1.1" ascii fullword
		$s3 = "wzsw_encrypt_buf" ascii fullword
		$s4 = "body:%d-%s" ascii fullword
		$s5 = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident" ascii fullword
		$s6 = "process_http_read_events" ascii fullword
		$op1 = { c4 34 42 00 02 30 63 00 40 10 60 00 09 ae 62 00 48 8e 62 00 cc }
		$op2 = { 27 f4 8c 46 27 f0 03 20 f8 09 00 60 28 21 }

	condition:
		uint16(0)==0x457f and filesize <600KB and (1 of ($x*) or 3 of them ) or 5 of them
}