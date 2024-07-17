import "pe"


rule SIGNATURE_BASE_Sofacy_Oct17_2 : FILE
{
	meta:
		description = "Detects Sofacy malware reported in October 2017"
		author = "Florian Roth (Nextron Systems)"
		id = "c820eab0-9b64-5718-8681-a4f515ee462b"
		date = "2017-10-23"
		modified = "2023-12-05"
		reference = "http://blog.talosintelligence.com/2017/10/cyber-conflict-decoy-document.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_sofacy_oct17_camp.yar#L49-L71"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c2736cf9efbb022590f4c23986531e645ac412a5b98a950b143f2d75a33e8063"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "ef027405492bc0719437eb58c3d2774cc87845f30c40040bbebbcc09a4e3dd18"

	strings:
		$x1 = "netwf.dll" fullword wide
		$s1 = "%s - %s - %2.2x" fullword wide
		$s2 = "%s - %lu" fullword ascii
		$s3 = "%s \"%s\", %s" fullword wide
		$s4 = "%j%Xjsf" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <90KB and (pe.imphash()=="13344e2a717849489bcd93692f9646f7" or (4 of them ))) or ( all of them )
}