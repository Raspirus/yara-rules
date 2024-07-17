rule SIGNATURE_BASE_MAL_Xbash_JS_Sep18 : FILE
{
	meta:
		description = "Detects XBash malware"
		author = "Florian Roth (Nextron Systems)"
		id = "e891d146-f92d-5144-a1f2-ad308e309870"
		date = "2018-09-18"
		modified = "2023-01-06"
		reference = "https://researchcenter.paloaltonetworks.com/2018/09/unit42-xbash-combines-botnet-ransomware-coinmining-worm-targets-linux-windows/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_xbash.yar#L50-L66"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "cf2f9006e0ab07f6ff1a0ce4946af34468f7c74143c853c5d77c6db725bb590a"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "f888dda9ca1876eba12ffb55a7a993bd1f5a622a30045a675da4955ede3e4cb8"

	strings:
		$s1 = "var path=WSHShell" fullword ascii
		$s2 = "var myObject= new ActiveXObject(" ascii
		$s3 = "window.resizeTo(0,0)" fullword ascii
		$s4 = "<script language=\"JScript\">" fullword ascii

	condition:
		filesize <5KB and 3 of them
}