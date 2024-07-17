
rule SIGNATURE_BASE_APT_WEBSHELL_PHP_Sandworm_May20_1 : FILE
{
	meta:
		description = "Detects GIF header PHP webshell used by Sandworm on compromised machines"
		author = "Florian Roth (Nextron Systems)"
		id = "b9ec02c2-fa83-5f21-95cf-3528047b2d01"
		date = "2020-05-28"
		modified = "2023-12-05"
		reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_sandworm_exim_expl.yar#L86-L101"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "0d10f618c7b465c7691d6054e994a76f56c12eb0a36d2d98b5accd2c1e2c1da7"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "dc074464e50502459038ac127b50b8c68ed52817a61c2f97f0add33447c8f730"
		hash2 = "538d713cb47a6b5ec6a3416404e0fc1ebcbc219a127315529f519f936420c80e"

	strings:
		$h1 = "GIF89a <?php $" ascii
		$s1 = "str_replace(" ascii

	condition:
		filesize <10KB and $h1 at 0 and $s1
}