rule SIGNATURE_BASE_Neuron_Common_Strings : FILE
{
	meta:
		description = "Rule for detection of Neuron based on commonly used strings"
		author = "NCSC UK"
		id = "168214d4-7436-531e-9c1f-48ca22215a1b"
		date = "2017-11-23"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_turla_neuron.yar#L9-L32"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29"
		logic_hash = "5f7a704fa0b6892b40868689c876e2f8252bb7319424212454408cbdf66f0b9f"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$strServiceName = "MSExchangeService" ascii
		$strReqParameter_1 = "cadataKey" wide
		$strReqParameter_3 = "cadata" wide
		$strReqParameter_4 = "cadataSig" wide
		$strEmbeddedKey = "PFJTQUtleVZhbHVlPjxNb2R1bHVzPnZ3WXRKcnNRZjVTcCtWVG9Rb2xuaEVkMHVwWDFrVElFTUNTNEFnRkRCclNm clpKS0owN3BYYjh2b2FxdUtseXF2RzBJcHV0YXhDMVRYazRoeFNrdEpzbHljU3RFaHBUc1l4OVBEcURabVVZVklVb HlwSFN1K3ljWUJWVFdubTZmN0JTNW1pYnM0UWhMZElRbnl1ajFMQyt6TUhwZ0xmdEc2b1d5b0hyd1ZNaz08L01vZH VsdXM+PEV4cG9uZW50PkFRQUI8L0V4cG9uZW50PjwvUlNBS2V5VmFsdWU+" wide
		$strDefaultKey = "8d963325-01b8-4671-8e82-d0904275ab06" wide
		$strIdentifier = "MSXEWS" wide
		$strListenEndpoint = "443/ews/exchange/" wide
		$strB64RegKeySubstring = "U09GVFdBUkVcTWljcm9zb2Z0XENyeXB0b2dyYXBo" wide
		$strName = "neuron_service" ascii
		$dotnetMagic = "BSJB" ascii

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and $dotnetMagic and 6 of ($str*)
}