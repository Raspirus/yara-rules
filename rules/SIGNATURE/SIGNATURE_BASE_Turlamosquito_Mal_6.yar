import "pe"


rule SIGNATURE_BASE_Turlamosquito_Mal_6 : FILE
{
	meta:
		description = "Detects malware sample from Turla Mosquito report"
		author = "Florian Roth (Nextron Systems)"
		id = "1c320b60-ec7a-5f87-b871-f55924351f8f"
		date = "2018-02-22"
		modified = "2023-12-05"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_turla_mosquito.yar#L105-L127"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "9ca6ae4313ad8f009b17188aa7184ff01a4b7e35926f3f68dc3aea12bffb9bb1"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "b79cdf929d4a340bdd5f29b3aeccd3c65e39540d4529b64e50ebeacd9cdee5e9"

	strings:
		$a1 = "/scripts/m/query.php?id=" fullword wide
		$a2 = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36" fullword wide
		$a3 = "GetUserNameW fails" fullword wide
		$s1 = "QVSWQQ" fullword ascii
		$s2 = "SRRRQP" fullword ascii
		$s3 = "QSVVQQ" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <500KB and (2 of ($a*) or 4 of them )
}