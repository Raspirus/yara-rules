
rule SIGNATURE_BASE_WEBSHELL_ASPX_Xsltransform_Aug21 : FILE
{
	meta:
		description = "Detects an ASPX webshell utilizing XSL Transformations"
		author = "Max Altgelt"
		id = "44254084-a717-59e6-a3ac-eca3c1c864a8"
		date = "2020-02-23"
		modified = "2023-12-05"
		reference = "https://gist.github.com/JohnHammond/cdae03ca5bc2a14a735ad0334dcb93d6"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/webshell_xsl_transform.yar#L1-L19"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "3ac0b50adc4c56769d0248e213e9426a22e0f5086bf081da57f835ff1c77b716"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$csharpshell = "Language=\"C#\"" nocase
		$x1 = "<root>1</root>"
		$x2 = ".LoadXml(System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String("
		$s1 = "XsltSettings.TrustedXslt"
		$s2 = "Xml.XmlUrlResolver"
		$s3 = "FromBase64String(Request[\""

	condition:
		filesize <500KB and $csharpshell and (1 of ($x*) or all of ($s*))
}