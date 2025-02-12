CloudFormation do

  export = external_parameters.fetch(:export_name, external_parameters[:component_name])

  Condition('WebACLEnabled', FnNot(FnEquals(Ref('WebACL'), '')))
  Condition('OverrideAliases', FnNot(FnEquals(Ref('OverrideAliases'), '')))

  tags = []
  tags << { Key: 'Environment', Value: Ref('EnvironmentName') }
  tags << { Key: 'EnvironmentType', Value: Ref('EnvironmentType') }

  distribution_config = {}
  if (comment.to_s.start_with?('{"Fn::'))
    distribution_config[:Comment] =  comment
  else
    distribution_config[:Comment] = FnSub(comment)
  end
  distribution_config[:Origins] = []

  origins = external_parameters.fetch(:origins, {})
  origins.each do |id,config|
    origin={
      Id: id,
      DomainName: Ref("#{id}OriginDomainName")
    }
    origin[:OriginPath] = config['origin_path'] if config.has_key?('origin_path')
    origin[:OriginCustomHeaders] = config['custom_headers'] if config.has_key?('custom_headers')
    case config['source']
    when 'loadbalancer', 'apigateway'
      origin[:CustomOriginConfig] = { HTTPPort: '80', HTTPSPort: '443' }
      origin[:CustomOriginConfig][:OriginKeepaliveTimeout] = config["keep_alive_timeout"] if config.has_key?('keep_alive_timeout')
      origin[:CustomOriginConfig][:OriginReadTimeout] = config["read_timeout"] if config.has_key?('read_timeout')
      origin[:CustomOriginConfig][:OriginSSLProtocols] = config['ssl_policy'] if config.has_key?('ssl_policy')
      origin[:CustomOriginConfig][:OriginProtocolPolicy] = config['protocol_policy']
    when 's3'

      use_access_identity = external_parameters.fetch(:use_access_identity, false)
      if (use_access_identity == true)
        CloudFront_CloudFrontOriginAccessIdentity("#{id}OriginAccessIdentity") {
          CloudFrontOriginAccessIdentityConfig({
            Comment: FnJoin("-", [Ref("EnvironmentName"), id, "CloudFrontOriginAccessIdentity"])
          })
        }
        origin[:S3OriginConfig] = { OriginAccessIdentity: FnSub("origin-access-identity/cloudfront/${#{id}OriginAccessIdentity}") }

        Output("#{id}OriginAccessIdentity") do
          Value(FnGetAtt("#{id}OriginAccessIdentity", 'S3CanonicalUserId'))
        end
      else
        CloudFront_OriginAccessControl("#{id}OriginAccessControl") {
          OriginAccessControlConfig({
            Description: FnJoin("-", [Ref("EnvironmentName"), id, "CloudFrontOriginAccessControl"]),
            Name: FnJoin('', [id, '.s3.', Ref('AWS::Region'), '.amazonaws.com']),
            OriginAccessControlOriginType: 's3',
            SigningBehavior: 'always',
            SigningProtocol: 'sigv4'
          })
        }
        origin[:OriginAccessControlId] = Ref("#{id}OriginAccessControl")

        Output("#{id}OriginAccessControl") do
          Value Ref("#{id}OriginAccessControl")
        end
      end

    end

    distribution_config[:Origins] << origin

  end

  default_root_object = external_parameters.fetch(:default_root_object, nil)
  ipv6 = external_parameters.fetch(:ipv6, nil)
  custom_error_responses = external_parameters.fetch(:custom_error_responses, nil)
  distribution_config[:DefaultRootObject] = default_root_object unless default_root_object.nil?
  distribution_config[:HttpVersion] = external_parameters[:http_version]
  distribution_config[:Enabled] = external_parameters[:enabled]
  distribution_config[:IPV6Enabled] = ipv6 unless ipv6.nil?
  distribution_config[:PriceClass] = Ref('PriceClass')
  distribution_config[:WebACLId] = FnIf('WebACLEnabled', Ref('WebACL'), Ref('AWS::NoValue'))
  distribution_config[:CustomErrorResponses] = custom_error_responses unless custom_error_responses.nil?

  logs = external_parameters.fetch(:logs, {})
  unless logs.empty?
    logging_config = {
      Bucket: FnSub(logs['bucket'])
    }

    logging_config[:IncludeCookies] = logs['include_cookies'] if logs.key?('include_cookies')
    logging_config[:Prefix] = FnSub(logs['prefix']) if logs.key?('prefix')

    distribution_config[:Logging] = logging_config
  end

  # SSL Settings
  distribution_config[:ViewerCertificate] = {}

  ssl = external_parameters[:ssl]
  case ssl['type']
  when 'acm'
    distribution_config[:ViewerCertificate][:AcmCertificateArn] = Ref('AcmCertificateArn')
  when 'iam'
    distribution_config[:ViewerCertificate][:IAMCertificateId] = Ref('IamCertificateArn')
  else
    distribution_config[:ViewerCertificate][:CloudFrontDefaultCertificate] = true
  end

  if !distribution_config[:ViewerCertificate].key?(:CloudFrontDefaultCertificate)
    distribution_config[:ViewerCertificate][:SslSupportMethod] = ssl.has_key?('support_method') ? ssl['support_method'] : "sni-only"
  end

  distribution_config[:ViewerCertificate][:MinimumProtocolVersion] = ssl.has_key?('minimum_protocol_version') ? ssl['minimum_protocol_version'] : "TLSv1.2_2018"

    # Cache policies
    cache_policies = external_parameters.fetch(:cache_policies, {})
    cache_policies.each do |policy, policy_config|
      cache_policy_config = {}
      cache_policy_config[:Comment] = policy_config['Comment'] if policy_config.has_key?('Comment')
      cache_policy_config[:DefaultTTL] = policy_config.has_key?('DefaultTTL') ? policy_config['DefaultTTL'] : Ref('DefaultTTL')
      cache_policy_config[:MaxTTL] = policy_config.has_key?('MaxTTL') ? policy_config['MaxTTL'] : Ref('MaxTTL')
      cache_policy_config[:MinTTL] = policy_config.has_key?('MinTTL') ? policy_config['MinTTL'] : Ref('MinTTL')
      cache_policy_config[:Name] = policy_config.has_key?('Name') ? policy_config['Name'] : "#{component_name}-#{policy}"
      cache_policy_config[:ParametersInCacheKeyAndForwardedToOrigin] = {}
      cache_policy_config[:ParametersInCacheKeyAndForwardedToOrigin][:CookiesConfig] = {}
      cache_policy_config[:ParametersInCacheKeyAndForwardedToOrigin][:CookiesConfig][:CookieBehavior] = policy_config.has_key?('CookieBehavior') ? policy_config['CookieBehavior'] : "none"
      cache_policy_config[:ParametersInCacheKeyAndForwardedToOrigin][:CookiesConfig][:Cookies] = policy_config['Cookies'] if policy_config.has_key?('Cookies')
      cache_policy_config[:ParametersInCacheKeyAndForwardedToOrigin][:EnableAcceptEncodingBrotli] = policy_config.has_key?('EnableAcceptEncodingBrotli') ? policy_config['EnableAcceptEncodingBrotli'] : false
      cache_policy_config[:ParametersInCacheKeyAndForwardedToOrigin][:EnableAcceptEncodingGzip] = policy_config.has_key?('EnableAcceptEncodingGzip') ? policy_config['EnableAcceptEncodingGzip'] : true
      cache_policy_config[:ParametersInCacheKeyAndForwardedToOrigin][:HeadersConfig] = {}
      cache_policy_config[:ParametersInCacheKeyAndForwardedToOrigin][:HeadersConfig][:HeaderBehavior] = policy_config.has_key?('HeaderBehavior') ? policy_config['HeaderBehavior'] : 'none'
      cache_policy_config[:ParametersInCacheKeyAndForwardedToOrigin][:HeadersConfig][:Headers] = policy_config['Headers'] if policy_config.has_key?('Headers')
      policy_safe = policy.gsub(/[-_.]/,"")
      CloudFront_CachePolicy("#{policy_safe}CloudFrontCachePolicy") {
        CachePolicyConfig cache_policy_config
      }
    end

    # Origin request policies
    origin_request_policies = external_parameters.fetch(:origin_request_policies, {})
    origin_request_policies.each do |request_policy, policy_config|
      request_policy_config = {}
      request_policy_config[:Comment] = policy_config['Comment'] if policy_config.has_key?('Comment')
      request_policy_config[:Name] = policy_config.has_key?('Name') ? policy_config['Name'] : "#{component_name}-#{request_policy}"
      request_policy_config[:CookiesConfig] = {}
      request_policy_config[:CookiesConfig][:CookieBehavior] = policy_config.has_key?('CookieBehavior') ? policy_config['CookieBehavior'] : "none"
      request_policy_config[:CookiesConfig][:Cookies] = policy_config['Cookies'] if policy_config.has_key?('Cookies')
      request_policy_config[:HeadersConfig] = {}
      request_policy_config[:HeadersConfig][:HeaderBehavior] = policy_config.has_key?('HeaderBehavior') ? policy_config['HeaderBehavior'] : 'none'
      request_policy_config[:HeadersConfig][:Headers] = policy_config['Headers'] if policy_config.has_key?('Headers')
      request_policy_config[:QueryStringsConfig] = {}
      request_policy_config[:QueryStringsConfig][:QueryStringBehavior] = policy_config.has_key?('QueryStringBehavior') ? policy_config['QueryStringBehavior'] : 'none'
      request_policy_config[:QueryStringsConfig][:QueryStrings] = policy_config['QueryStrings'] if policy_config.has_key?('QueryStrings')
      request_policy_safe = request_policy.gsub(/[-_.]/,"")
      CloudFront_OriginRequestPolicy("#{request_policy_safe}CloudFrontOriginRequestPolicy") {
        OriginRequestPolicyConfig request_policy_config
      }
    end

    # Functions
    functions = external_parameters.fetch(:functions, {})
    functions.each do |func, fconfig|
      func_safe = func.gsub(/[-_.]/,"")
      func_conf = {}
      func_conf['Comment'] = fconfig.has_key?('Comment') ? fconfig['Comment'] : FnJoin(" ", ["The", func, "CloudFrontFunction"])
      func_conf['Runtime'] = fconfig.has_key?('Runtime') ? fconfig['Runtime'] : "cloudfront-js-2.0"
      func_conf['KeyValueStoreAssociations'] = fconfig['KeyValueStoreAssociations'] if fconfig.has_key?('KeyValueStoreAssociations')
      CloudFront_Function("#{func_safe}CloudFrontFunction") do
        AutoPublish fconfig.has_key?('AutoPublish') ? fconfig['AutoPublish'] : true
        FunctionCode fconfig['code']
        Name fconfig.has_key?('Name') ? fconfig['Name'] : func_safe
        FunctionConfig func_conf
      end
    end
  
    # Cache behaviours
    behaviours = external_parameters.fetch(:behaviours, {})
    behaviours.each do |behaviour, config|
      if behaviour == 'default'
        if (config.has_key?('CachePolicyId') and config.has_key?('ForwardedValues'))
          config.delete('ForwardedValues')
          policy_safe = config['CachePolicyId'].gsub(/[-_.]/,"")
          config['CachePolicyId'] = { "Ref" => "#{policy_safe}CloudFrontCachePolicy" }
        end
        request_policy_safe = config['OriginRequestPolicyId'].gsub(/[-_.]/,"") if config.has_key?('OriginRequestPolicyId')
        config['OriginRequestPolicyId'] = { "Ref" => "#{request_policy_safe}CloudFrontOriginRequestPolicy" } if config.has_key?('OriginRequestPolicyId')
        if config.has_key?('FunctionAssociation')
          if config['FunctionAssociation'].has_key?('Function')
            func_safe = config['FunctionAssociation']['Function'].gsub(/[-_.]/,"")
            config['FunctionAssociation'].delete('Function')
            config['FunctionAssociation']['EventType'] = 'viewer-request' if not config['FunctionAssociation'].has_key?('EventType')
            config['FunctionAssociation']['FunctionARN'] = FnGetAtt("#{func_safe}CloudFrontFunction", "FunctionARN")
          end
        end
        distribution_config[:DefaultCacheBehavior] = config
      else
        config.each do |x|
          if (x.has_key?('CachePolicyId') and x.has_key?('ForwardedValues'))
            x.delete('ForwardedValues')
            policy_safe = x['CachePolicyId'].gsub(/[-_.]/,"")
            x['CachePolicyId'] = { "Ref" => "#{policy_safe}CloudFrontCachePolicy" }
          end
          request_policy_safe = x['OriginRequestPolicyId'].gsub(/[-_.]/,"") if x.has_key?('OriginRequestPolicyId')
          x['OriginRequestPolicyId'] = { "Ref" => "#{request_policy_safe}CloudFrontOriginRequestPolicy" } if x.has_key?('OriginRequestPolicyId')
          if x.has_key?('FunctionAssociation')
            if x['FunctionAssociation'].has_key?('Function')
              func_safe = x['FunctionAssociation']['Function'].gsub(/[-_.]/,"")
              x['FunctionAssociation'].delete('Function')
              x['FunctionAssociation']['EventType'] = 'viewer-request' if not x['FunctionAssociation'].has_key?('EventType')
              x['FunctionAssociation']['FunctionARN'] = FnGetAtt("#{func_safe}CloudFrontFunction", "FunctionARN")
            end
          end
        end
        distribution_config[:CacheBehaviors] = config
      end
    end

  # Aliases
  aliases_map = external_parameters.fetch(:aliases_map, {})
  aliases = external_parameters.fetch(:aliases, [])
  if aliases_map.any?
    map = {}
    aliases_map.each { |k,v| map[k.to_sym] = { records: v.join(',') } }
    Mapping('aliases', map)
    distribution_config[:Aliases] = FnSplit(',', FnFindInMap('aliases', Ref('EnvironmentName'), 'records'))
  elsif aliases.any?
    distribution_config[:Aliases] = FnIf('OverrideAliases', FnSplit(',', Ref('OverrideAliases')), aliases.map { |a| FnSub(a) })
  end

  # Geo Restrictions
  geo_restrictions = external_parameters.fetch(:geo_restrictions, {})
  if geo_restrictions.any?
    if geo_restrictions['locations'].any? && geo_restrictions['type']
      restriction = {}
      geo_restriction = {}
      geo_restriction[:Locations] = geo_restrictions['locations']
      geo_restriction[:RestrictionType] = geo_restrictions['type']
      restriction[:GeoRestriction] = geo_restriction
      distribution_config[:Restrictions] = restriction
    end
  end

  CloudFront_Distribution(:Distribution) {
    DistributionConfig distribution_config
    Tags tags
  }

  dns_records = external_parameters.fetch(:dns_records, {})
  dns_records.each_with_index do |record, index|
    name = (['apex',''].include? record) ? dns_format : FnJoin('.', [record, dns_format, ''])
    Route53_RecordSet("CloudfrontDns#{index}") do
      if (dns_format.to_s.start_with?('{"Fn::'))
        HostedZoneName FnJoin('', [dns_format, '.'])
        Name name
      else
        HostedZoneName FnSub("#{dns_format}.") 
        Name FnSub(name)
      end
      Type 'A'
      AliasTarget ({
          DNSName: FnGetAtt(:Distribution, :DomainName),
          HostedZoneId: 'Z2FDTNDATAQYW2'
      })
    end
  end

  Output('DomainName') do
    Value(FnGetAtt('Distribution', 'DomainName'))
    Export FnJoin("-", [Ref("EnvironmentName"), export, "DomainName"])
  end

  Output('DistributionId') do
    Value(FnGetAtt('Distribution', 'Id'))
    Export FnJoin("-", [Ref("EnvironmentName"), export, "DistributionId"])
  end

end
