import "pe"


import "pe"


rule SIGNATURE_BASE_Hvs_APT37_Webshell_Img_Thumbs_Asp : FILE
{
	meta:
		description = "Webshell named img.asp, thumbs.asp or thumb.asp used by APT37"
		author = "Moritz Oettle"
		id = "e45d4507-81de-5f72-9ce2-4f0e3e5c62b1"
		date = "2020-12-15"
		modified = "2023-12-05"
		reference = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_lazarus_dec20.yar#L68-L95"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "94d2448d3794ae3f29678a7337473d259b5cfd1c7f703fe53ee6c84dd10a48ef"
		logic_hash = "58ccee11c08330c8cd4148e623a2e59e024d6d5f3067331dbdd962d0f6a8daa4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "strMsg = \"E : F\"" fullword ascii
		$s2 = "strMsg = \"S : \" & Len(fileData)" fullword ascii
		$s3 = "Left(workDir, InStrRev(workDir, \"/\")) & \"video\""
		$a1 = "Server.CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
		$a2 = "Dim tmpPath, workDir" fullword ascii
		$a3 = "Dim objFSO, objTextStream" fullword ascii
		$a4 = "workDir = Request.ServerVariables(\"URL\")" fullword ascii
		$a5 = "InStrRev(workDir, \"/\")" ascii
		$g1 = "WriteFile = 0" fullword ascii
		$g2 = "fileData = Request.Form(\"fp\")" fullword ascii
		$g3 = "fileName = Request.Form(\"fr\")" fullword ascii
		$g4 = "Err.Clear()" fullword ascii
		$g5 = "Option Explicit" fullword ascii

	condition:
		filesize <2KB and ((1 of ($s*)) or (3 of ($a*)) or (5 of ($g*)))
}