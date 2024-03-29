CfhighlanderTemplate do

  Parameters do
    ComponentParam 'EnvironmentName', 'dev', isGlobal: true
    ComponentParam 'EnvironmentType', 'development', allowedValues: ['development','production'], isGlobal: true
    ComponentParam 'DnsDomain', isGlobal: true
    ComponentParam 'EnableLambdaFunctionAssociations', 'false', allowedValues: ['true', 'false']

    origins.each do |id,config|
      ComponentParam "#{id}OriginDomainName"
      ComponentParam "#{id}OriginAccessIdentityInput", '' if config['source'] == 's3'
    end if (defined? origins) && (origins.any?)

    case ssl['type']
    when 'acm'
      ComponentParam 'AcmCertificateArn'
    when 'iam'
      ComponentParam 'IamCertificateArn'
    end

    ComponentParam 'PriceClass', 'PriceClass_All', allowedValues: ['PriceClass_All','PriceClass_200', 'PriceClass_100']
    ComponentParam 'WebACL'
    ComponentParam 'MinTTL',      0
    ComponentParam 'MaxTTL',      31536000
    ComponentParam 'DefaultTTL',  86400

    if (defined? aliases_map) && (aliases_map.any?)
      ComponentParam 'AliasMap', aliases_map.keys[0], allowedValues: aliases_map.map { |k,v| k }
    end

    ComponentParam 'OverrideAliases', ''

  end


end
