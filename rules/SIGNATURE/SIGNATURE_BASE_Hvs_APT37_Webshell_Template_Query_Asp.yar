import "pe"


rule SIGNATURE_BASE_Hvs_APT37_Webshell_Template_Query_Asp : FILE
{
	meta:
		description = "Webshell named template-query.aspimg.asp used by APT37"
		author = "Moritz Oettle"
		id = "dc006b46-4c51-59cd-8b7d-adbfec86cd2e"
		date = "2020-12-15"
		modified = "2023-12-05"
		reference = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_lazarus_dec20.yar#L97-L120"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "961a66d01c86fa5982e0538215b17fb9fae2991331dfea812b8c031e2ceb0d90"
		logic_hash = "d8bd017e9103bddb0b8a86effa8a4b0617b54bd643bcc36b6f678a3e60f8559f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$g1 = "server.scripttimeout=600" fullword ascii
		$g2 = "response.buffer=true" fullword ascii
		$g3 = "response.expires=-1" fullword ascii
		$g4 = "session.timeout=600" fullword ascii
		$a1 = "redhat hacker" ascii
		$a2 = "want_pre.asp" ascii
		$a3 = "vgo=\"admin\"" ascii
		$a4 = "ywc=false" ascii
		$s1 = "public  br,ygv,gbc,ydo,yka,wzd,sod,vmd" fullword ascii

	condition:
		filesize >70KB and filesize <200KB and ((1 of ($s*)) or (2 of ($a*)) or (3 of ($g*)))
}