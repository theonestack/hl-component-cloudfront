CfhighlanderTemplate do
  Name 'cloudfront'
  Description "cloudfront - #{component_version}"

  Parameters do
    ComponentParam 'EnvironmentName', 'dev', isGlobal: true
    ComponentParam 'EnvironmentType', 'development', allowedValues: ['development','production'], isGlobal: true
    ComponentParam 'DnsDomain', isGlobal: true

    origins.each do |id,config|
      ComponentParam "#{id}OriginDomainName"
    end if (defined? origins) && (origins.any?)

    case ssl['type']
    when 'acm'
      ComponentParam 'AcmCertificateArn'
    when 'iam'
      ComponentParam 'IamCertificateArn'
    end

    ComponentParam 'PriceClass', 'PriceClass_All', allowedValues: ['PriceClass_All','PriceClass_200', 'PriceClass_100']
    ComponentParam 'WebACL'

    if (defined? aliases_map) && (aliases_map.any?)
      ComponentParam 'AliasMap', aliases_map.keys[0], allowedValues: aliases_map.map { |k,v| k }
    end

  end


end
