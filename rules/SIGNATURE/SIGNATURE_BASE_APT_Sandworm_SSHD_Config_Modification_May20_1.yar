
rule SIGNATURE_BASE_APT_Sandworm_SSHD_Config_Modification_May20_1 : FILE
{
	meta:
		description = "Detects ssh config entry inserted by Sandworm on compromised machines"
		author = "Florian Roth (Nextron Systems)"
		id = "dd60eeb7-3d4b-5a6a-8054-50c617ee8c73"
		date = "2020-05-28"
		modified = "2023-12-05"
		reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_sandworm_exim_expl.yar#L33-L49"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "5775588b3a9d44e9eb2c8ef0f50351d7e3b06f1005f669775fae7187900d5999"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "dc074464e50502459038ac127b50b8c68ed52817a61c2f97f0add33447c8f730"
		hash2 = "538d713cb47a6b5ec6a3416404e0fc1ebcbc219a127315529f519f936420c80e"

	strings:
		$x1 = "AllowUsers mysql_db" ascii
		$a1 = "ListenAddress" ascii fullword

	condition:
		filesize <10KB and all of them
}