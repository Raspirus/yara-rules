rule SIGNATURE_BASE_MAL_Visel_Sample_May18_1 : FILE
{
	meta:
		description = "Detects Visel malware sample from Burning Umbrella report"
		author = "Florian Roth (Nextron Systems)"
		id = "a244461a-380c-56e6-a891-131f6e13c280"
		date = "2018-05-04"
		modified = "2023-12-05"
		reference = "https://401trg.pw/burning-umbrella/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_winnti_burning_umbrella.yar#L442-L460"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "3200e3224e037a116451b09ce265c1794a05406876376531ac81eb720fcb6945"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "35db8e6a2eb5cf09cd98bf5d31f6356d0deaf4951b353fc513ce98918b91439c"

	strings:
		$s2 = "print32.dll" fullword ascii
		$s3 = "c:\\a\\b.txt" fullword ascii
		$s4 = "\\temp\\s%d.dat" wide

	condition:
		uint16(0)==0x5a4d and filesize <200KB and (pe.exports("szFile") or 2 of them )
}