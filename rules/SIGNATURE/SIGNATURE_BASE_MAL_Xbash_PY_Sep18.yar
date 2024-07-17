rule SIGNATURE_BASE_MAL_Xbash_PY_Sep18 : FILE
{
	meta:
		description = "Detects Xbash malware"
		author = "Florian Roth (Nextron Systems)"
		id = "97512fe8-002f-5cbc-a915-d55c087fbef7"
		date = "2018-09-18"
		modified = "2023-12-05"
		reference = "https://researchcenter.paloaltonetworks.com/2018/09/unit42-xbash-combines-botnet-ransomware-coinmining-worm-targets-linux-windows/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_xbash.yar#L13-L25"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "d686c42e6bf440507735f846463f2df5fbf4f7bd5f5656883655a5278a1fc252"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "7a18c7bdf0c504832c8552766dcfe0ba33dd5493daa3d9dbe9c985c1ce36e5aa"

	strings:
		$s1 = { 73 58 62 61 73 68 00 00 00 00 00 00 00 00 }

	condition:
		uint16(0)==0x457f and filesize <10000KB and 1 of them
}