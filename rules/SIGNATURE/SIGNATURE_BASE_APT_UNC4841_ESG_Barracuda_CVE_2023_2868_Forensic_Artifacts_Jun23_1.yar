
rule SIGNATURE_BASE_APT_UNC4841_ESG_Barracuda_CVE_2023_2868_Forensic_Artifacts_Jun23_1 : SCRIPT CVE_2023_2868
{
	meta:
		description = "Detects forensic artifacts found in the exploitation of CVE-2023-2868 in Barracuda ESG devices by UNC4841"
		author = "Florian Roth"
		id = "50518fa1-33de-5fe5-b957-904d976fb29a"
		date = "2023-06-15"
		modified = "2023-06-16"
		reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_barracuda_esg_unc4841_jun23.yar#L2-L28"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "fa7cac1e0f6cb6fa3ac271c1fff0039ff182b6859920b4eca25541457654acde"
		score = 75
		quality = 85
		tags = "SCRIPT, CVE-2023-2868"

	strings:
		$x01 = "=;ee=ba;G=s;_ech_o $abcdefg_${ee}se64" ascii
		$x02 = ";echo $abcdefg | base64 -d | sh" ascii
		$x03 = "setsid sh -c \"mkfifo /tmp/p" ascii
		$x04 = "sh -i </tmp/p 2>&1" ascii
		$x05 = "if string.match(hdr:body(), \"^[%w%+/=" ascii
		$x06 = "setsid sh -c \"/sbin/BarracudaMailService eth0\""
		$x07 = "echo \"set the bvp ok\""
		$x08 = "find ${path} -type f ! -name $excludeFileNameKeyword | while read line ;"
		$x09 = " /mail/mstore | xargs -i cp {} /usr/share/.uc/"
		$x10 = "tar -T /mail/mstore/tmplist -czvf "
		$sa1 = "sh -c wget --no-check-certificate http"
		$sa2 = ".tar;chmod +x "

	condition:
		1 of ($x*) or all of ($sa*)
}