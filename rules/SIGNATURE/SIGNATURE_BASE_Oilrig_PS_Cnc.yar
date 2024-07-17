
rule SIGNATURE_BASE_Oilrig_PS_Cnc : FILE
{
	meta:
		description = "Powershell CnC using DNS queries"
		author = "Markus Neis"
		id = "cbc5689c-37ff-59b6-9e3a-7d8577021f70"
		date = "2018-03-22"
		modified = "2023-12-05"
		reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_oilrig_chafer_mar18.yar#L94-L107"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "0566f0707021af0d08426eec497292098273d46b020a5f0be6b98835ceeb82bc"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "9198c29a26f9c55317b4a7a722bf084036e93a41ba4466cbb61ea23d21289cfa"

	strings:
		$x1 = "(-join $base32filedata[$uploadedCompleteSize..$($uploadedCompleteSize" fullword ascii
		$s2 = "$hostname = \"D\" + $fileID + (-join ((65..90) + (48..57) + (97..122)|" ascii

	condition:
		filesize <40KB and 1 of them
}