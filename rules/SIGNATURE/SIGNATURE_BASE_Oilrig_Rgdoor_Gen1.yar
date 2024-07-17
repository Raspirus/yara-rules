rule SIGNATURE_BASE_Oilrig_Rgdoor_Gen1 : FILE
{
	meta:
		description = "Detects RGDoor backdoor used by OilRig group"
		author = "Florian Roth (Nextron Systems)"
		id = "68ac1f35-4eaa-5899-b66c-296d7c5fa462"
		date = "2018-01-27"
		modified = "2023-12-05"
		reference = "https://researchcenter.paloaltonetworks.com/2018/01/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_oilrig_rgdoor.yar#L13-L39"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "896900f788337327d444495ba0cd4c7c327bb4f9166bc2a981a348cf2c34cbdb"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a9c92b29ee05c1522715c7a2f9c543740b60e36373cb47b5620b1f3d8ad96bfa"

	strings:
		$c1 = { 00 63 6D 64 24 00 00 00 00 72 00 00 00 00 00 00 00 75 70 6C 6F
              61 64 24 }
		$c2 = { 63 61 6E 27 74 20 6F 70 65 6E 20 66 69 6C 65 3A 20 00 00 00 00
              00 00 00 64 6F 77 6E 6C 6F 61 64 24 }
		$s1 = "MyNativeModule.dll" fullword ascii
		$s2 = "RGSESSIONID=" fullword ascii
		$s3 = "download$" fullword ascii
		$s4 = ".?AVCHelloWorld@@" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <600KB and (pe.imphash()=="47cb127aad6c7c9954058e61a2a6429a" or 1 of ($c*) or 2 of them )
}