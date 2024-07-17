rule SIGNATURE_BASE_Rehashed_RAT_1 : FILE
{
	meta:
		description = "Detects malware from Rehashed RAT incident"
		author = "Florian Roth (Nextron Systems)"
		id = "24536421-3f8f-58f3-8245-06c519d7a21a"
		date = "2017-09-08"
		modified = "2023-12-05"
		reference = "https://blog.fortinet.com/2017/09/05/rehashed-rat-used-in-apt-campaign-against-vietnamese-organizations"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_rehashed_rat.yar#L13-L39"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "06a98e87d931bdea697a2cf3de604f03654f9aa2b3f2346e78ba92e492c0fc7c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "37bd97779e854ea2fc43486ddb831a5acfd19cf89f06823c9fd3b20134cb1c35"

	strings:
		$x1 = "C:\\Users\\hoogle168\\Desktop\\"
		$x2 = "\\NewCoreCtrl08\\Release\\NewCoreCtrl08.pdb" ascii
		$s1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729" ascii
		$s2 = "NewCoreCtrl08.dll" fullword ascii
		$s3 = "GET /%s%s%s%s HTTP/1.1" fullword ascii
		$s4 = "http://%s:%d/%s%s%s%s" fullword ascii
		$s5 = "MyTmpFile.Dat" fullword wide
		$s6 = "root\\%s" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <800KB and (pe.imphash()=="893212784d01f11aed9ebb42ad2561fc" or pe.exports("ProcessTrans") or (1 of ($x*) or 4 of them ))) or ( all of them )
}