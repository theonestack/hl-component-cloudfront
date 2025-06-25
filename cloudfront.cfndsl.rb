CloudFormation do

  origins = external_parameters.fetch(:origins, {})
  
  dependencies_list = []
  cloudfront_component_name = external_parameters.fetch(:cloudfront_component_name, nil)
  if !cloudfront_component_name.nil?
    origins.filter{|k, v| (v['source'] == 's3') && (v['type'] == 'create_if_not_exists')}.each do |id, config|
      if (origins.filter{|k, v| (v['source'] == 's3')}.map.with_index{|(k,v),i| k.to_s == id ? i.to_i : nil}.compact == [0])
        id = ""
      end
      CloudFormation_WaitConditionHandle("#{id}Bucket") do
        Type 'AWS::CloudFormation::WaitConditionHandle'
      end
      dependencies_list << "#{id}Bucket"
    end
  end
  
  export = external_parameters.fetch(:export_name, external_parameters[:component_name])

  Condition('OverrideAliases', FnNot(FnEquals(Ref('OverrideAliases'), '')))

  tags = []
  tags << { Key: 'Environment', Value: Ref('EnvironmentName') }
  tags << { Key: 'EnvironmentType', Value: Ref('EnvironmentType') }

  distribution_config = {}
  if (comment.to_s.start_with?('{"Fn::'))
    distribution_config[:Comment] = comment
  else
    distribution_config[:Comment] = FnSub(comment)
  end
  distribution_config[:Origins] = []

  origins.each do |id, config|
    origin = {
      Id: id,
      DomainName: Ref("#{id}OriginDomainName")
    }
    origin[:OriginPath] = config['origin_path'] if config.has_key?('origin_path')
    origin[:OriginCustomHeaders] = config['custom_headers'] if config.has_key?('custom_headers')
    case config['source']
    when 'vpc'
      if config.has_key?("arn")
          config['default-caching-policy-id'] = '83da9c7e-98b4-4e11-a168-04f0df8e2c65'
          vpc_origin_config = {}
          vpc_origin_config[:HTTPPort] = config.has_key?('http_port') ? config["http_port"] : 80
          vpc_origin_config[:HTTPSPort] = config.has_key?('https_port') ? config["https_port"] : 443
          vpc_origin_config[:Arn] = config["arn"]
          vpc_origin_config[:Name] = config.has_key?('name') ? config["name"] : FnJoin("-", [Ref("EnvironmentName"), id, "vpc", "origin"])
          vpc_origin_config[:OriginProtocolPolicy] = config['origin_protocol_policy'] if config.has_key?('origin_protocol_policy')
          vpc_origin_config[:OriginSSLProtocols] = config['origin_ssl_protocols'] if config.has_key?('origin_ssl_protocols')
          CloudFront_VpcOrigin("#{id}VPCOrigin") {
            VpcOriginEndpointConfig vpc_origin_config
            Tags tags
          }
          origin[:VpcOriginConfig] = {}
          origin[:VpcOriginConfig][:OriginKeepaliveTimeout] = config["keep_alive_timeout"] if config.has_key?('keep_alive_timeout')
          origin[:VpcOriginConfig][:OriginReadTimeout] = config["read_timeout"] if config.has_key?('read_timeout')
          origin[:VpcOriginConfig][:VpcOriginId] = Ref("#{id}VPCOrigin")
      end
    when 'loadbalancer', 'apigateway'
      config['default-caching-policy-id'] = '83da9c7e-98b4-4e11-a168-04f0df8e2c65'
      origin[:CustomOriginConfig] = { HTTPPort: '80', HTTPSPort: '443' }
      origin[:CustomOriginConfig][:OriginKeepaliveTimeout] = config["keep_alive_timeout"] if config.has_key?('keep_alive_timeout')
      origin[:CustomOriginConfig][:OriginReadTimeout] = config["read_timeout"] if config.has_key?('read_timeout')
      origin[:CustomOriginConfig][:OriginSSLProtocols] = config['ssl_policy'] if config.has_key?('ssl_policy')
      origin[:CustomOriginConfig][:OriginProtocolPolicy] = config['protocol_policy']
    when 's3'
      config['default-caching-policy-id'] = '658327ea-f89d-4fab-a63d-7e88639e58f6'
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
        origin[:S3OriginConfig] = {}  # If you're using origin access control (OAC) instead of origin access identity, specify an empty OriginAccessIdentity element.
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
  distribution_config[:WebACLId] = Ref('WebACL')
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
    cache_policy_config[:Name] = policy_config.has_key?('Name') ? policy_config['Name'] : FnJoin('-', [Ref('EnvironmentName'), "#{component_name}-#{policy}"])
    cache_policy_config[:ParametersInCacheKeyAndForwardedToOrigin] = {}
    cache_policy_config[:ParametersInCacheKeyAndForwardedToOrigin][:CookiesConfig] = {}
    cache_policy_config[:ParametersInCacheKeyAndForwardedToOrigin][:CookiesConfig][:CookieBehavior] = policy_config.has_key?('CookieBehavior') ? policy_config['CookieBehavior'] : "none"
    cache_policy_config[:ParametersInCacheKeyAndForwardedToOrigin][:CookiesConfig][:Cookies] = policy_config['Cookies'] if policy_config.has_key?('Cookies')
    cache_policy_config[:ParametersInCacheKeyAndForwardedToOrigin][:EnableAcceptEncodingBrotli] = policy_config.has_key?('EnableAcceptEncodingBrotli') ? policy_config['EnableAcceptEncodingBrotli'] : false
    cache_policy_config[:ParametersInCacheKeyAndForwardedToOrigin][:EnableAcceptEncodingGzip] = policy_config.has_key?('EnableAcceptEncodingGzip') ? policy_config['EnableAcceptEncodingGzip'] : true
    cache_policy_config[:ParametersInCacheKeyAndForwardedToOrigin][:HeadersConfig] = {}
    cache_policy_config[:ParametersInCacheKeyAndForwardedToOrigin][:HeadersConfig][:HeaderBehavior] = policy_config.has_key?('HeaderBehavior') ? policy_config['HeaderBehavior'] : 'none'
    cache_policy_config[:ParametersInCacheKeyAndForwardedToOrigin][:HeadersConfig][:Headers] = policy_config['Headers'] if policy_config.has_key?('Headers')
    cache_policy_config[:ParametersInCacheKeyAndForwardedToOrigin][:QueryStringsConfig] = {}
    cache_policy_config[:ParametersInCacheKeyAndForwardedToOrigin][:QueryStringsConfig][:QueryStringBehavior] = policy_config.has_key?('QueryStringBehavior') ? policy_config['QueryStringBehavior'] : 'none'
    cache_policy_config[:ParametersInCacheKeyAndForwardedToOrigin][:QueryStringsConfig][:QueryStrings] = policy_config['QueryStrings'] if policy_config.has_key?('QueryStrings')
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
    request_policy_config[:Name] = policy_config.has_key?('Name') ? policy_config['Name'] : FnJoin('-', [Ref('EnvironmentName'), "#{component_name}-#{request_policy}"])
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

  # Response headers policies
  response_headers_policies = external_parameters.fetch(:response_headers_policies, {})
  response_headers_policies.each do |response_policy, policy_config|
    response_headers_policy_config = {}
    response_headers_policy_config[:Comment] = policy_config['Comment'] if policy_config.has_key?('Comment')
    response_headers_policy_config[:CorsConfig] = policy_config['CorsConfig'] if policy_config.has_key?('CorsConfig')
    response_headers_policy_config[:CustomHeadersConfig] = {} if policy_config.has_key?('CustomHeadersConfig')
    response_headers_policy_config[:CustomHeadersConfig]['Items'] = policy_config['CustomHeadersConfig'] if policy_config.has_key?('CustomHeadersConfig')
    response_headers_policy_config[:Name] = policy_config.has_key?('Name') ? policy_config['Name'] : FnJoin('-', [Ref('EnvironmentName'), "#{component_name}-#{response_policy}"])
    response_headers_policy_config[:RemoveHeadersConfig] = {} if policy_config.has_key?('RemoveHeadersConfig')
    response_headers_policy_config[:RemoveHeadersConfig]['Items'] = policy_config['RemoveHeadersConfig'] if policy_config.has_key?('RemoveHeadersConfig')
    response_headers_policy_config[:SecurityHeadersConfig] = policy_config['SecurityHeadersConfig'] if policy_config.has_key?('SecurityHeadersConfig')
    response_headers_policy_config[:ServerTimingHeadersConfig] = policy_config['ServerTimingHeadersConfig'] if policy_config.has_key?('ServerTimingHeadersConfig')
    response_policy_safe = response_policy.gsub(/[-_.]/,"")
    CloudFront_ResponseHeadersPolicy("#{response_policy_safe}CloudFrontResponseHeadersPolicy") {
      ResponseHeadersPolicyConfig response_headers_policy_config
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
      FunctionCode FunctionCode ((fconfig['code'] if fconfig.has_key?('code')) || (fconfig['FunctionCode'] if fconfig.has_key?('FunctionCode')))
      Name fconfig.has_key?('Name') ? fconfig['Name'] : func
      FunctionConfig func_conf
    end
  end
  
  # Cache behaviours
  behaviours = external_parameters.fetch(:behaviours, {})
  behaviours.each do |behaviour, config|
    if behaviour == 'default'
    # What if origin does not exists? - perform check
      if (config.has_key?('TargetOriginId') and (!config['TargetOriginId'].nil?) and (origins.keys.include? config['TargetOriginId']))
        # What if the caching policy not defined? - perform check
        if (config.has_key?('CachePolicyId') and (!config['CachePolicyId'].nil?) and (cache_policies.keys.include? config['CachePolicyId']))
          config.delete('ForwardedValues')
          policy_safe = config['CachePolicyId'].gsub(/[-_.]/,"")
          config['CachePolicyId'] = { "Ref" => "#{policy_safe}CloudFrontCachePolicy" }
        else
          config['CachePolicyId'] = origins[config['TargetOriginId']]['default-caching-policy-id']
          if (config.has_key?('OriginRequestPolicyId') and (not config['OriginRequestPolicyId'].nil?))
            if (origin_request_policies.has_key?(config['OriginRequestPolicyId']) and (origin_request_policies[config['OriginRequestPolicyId']]['QueryStringBehavior'] != 'none'))
              config['CachePolicyId'] = '4cc15a8a-d715-48a4-82b8-cc0b614638fe' # UseOriginCacheControlHeaders-QueryStrings
            end
          end
        end
        # What if the request policy not defined? - perform check
        if (config.has_key?('OriginRequestPolicyId') and (!config['OriginRequestPolicyId'].nil?) and (origin_request_policies.keys.include? config['OriginRequestPolicyId']))
          request_policy_safe = config['OriginRequestPolicyId'].gsub(/[-_.]/,"")
          config['OriginRequestPolicyId'] = { "Ref" => "#{request_policy_safe}CloudFrontOriginRequestPolicy" }
        else
          config.delete('OriginRequestPolicyId')
        end
        # What if the response headers policy not defined? - perform check
        if (config.has_key?('ResponseHeadersPolicyId') and (!config['ResponseHeadersPolicyId'].nil?) and (response_headers_policies.keys.include? config['ResponseHeadersPolicyId']))
          response_policy_safe = config['ResponseHeadersPolicyId'].gsub(/[-_.]/,"")
          config['ResponseHeadersPolicyId'] = { "Ref" => "#{response_policy_safe}CloudFrontResponseHeadersPolicy" }
        else
          config.delete('ResponseHeadersPolicyId')
        end
        if config.has_key?('FunctionAssociations')
          config['FunctionAssociations'].uniq{ |k| k['EventType'] }.each do |assoc|
            # What if function is not defined? - perform check
            if (assoc.has_key?('Function') and (!assoc['Function'].nil?) and (functions.keys.include? assoc['Function']))
              func_safe = assoc['Function'].gsub(/[-_.]/,"")
              assoc['EventType'] = 'viewer-request' if not assoc.has_key?('EventType')
              assoc['FunctionARN'] = FnGetAtt("#{func_safe}CloudFrontFunction", "FunctionARN")
              assoc.delete('Function') if assoc.has_key?('Function')
            else
              config['FunctionAssociations'].delete(assoc)
            end
          end
        end
        distribution_config[:DefaultCacheBehavior] = config
      end
    else
      config.each do |x|
      # What if origin does not exists? - perform check
        if (x.has_key?('TargetOriginId') and (!x['TargetOriginId'].nil?) and (origins.keys.include? x['TargetOriginId']))
          # What if the caching policy not defined? - perform check
          if (x.has_key?('CachePolicyId') and (!x['CachePolicyId'].nil?) and (cache_policies.keys.include? x['CachePolicyId']))
            x.delete('ForwardedValues')
            policy_safe = x['CachePolicyId'].gsub(/[-_.]/,"")
            x['CachePolicyId'] = { "Ref" => "#{policy_safe}CloudFrontCachePolicy" }
          else
            x['CachePolicyId'] = origins[x['TargetOriginId']]['default-caching-policy-id']
            if (x.has_key?('OriginRequestPolicyId') and (not x['OriginRequestPolicyId'].nil?))
              if (origin_request_policies.has_key?(x['OriginRequestPolicyId']) and (origin_request_policies[x['OriginRequestPolicyId']]['QueryStringBehavior'] != 'none'))
                x['CachePolicyId'] = '4cc15a8a-d715-48a4-82b8-cc0b614638fe' # UseOriginCacheControlHeaders-QueryStrings
              end
            end
          end
          # What if the request policy not defined? - perform check
          if (x.has_key?('OriginRequestPolicyId') and (!x['OriginRequestPolicyId'].nil?) and (origin_request_policies.keys.include? x['OriginRequestPolicyId']))
            request_policy_safe = x['OriginRequestPolicyId'].gsub(/[-_.]/,"")
            x['OriginRequestPolicyId'] = { "Ref" => "#{request_policy_safe}CloudFrontOriginRequestPolicy" }
          else
            x.delete('OriginRequestPolicyId')
          end
          # What if the response headers policy not defined? - perform check
          if (x.has_key?('ResponseHeadersPolicyId') and (!x['ResponseHeadersPolicyId'].nil?) and (response_headers_policies.keys.include? x['ResponseHeadersPolicyId']))
            response_policy_safe = x['ResponseHeadersPolicyId'].gsub(/[-_.]/,"")
            x['ResponseHeadersPolicyId'] = { "Ref" => "#{response_policy_safe}CloudFrontResponseHeadersPolicy" }
          else
            x.delete('ResponseHeadersPolicyId')
          end
          if x.has_key?('FunctionAssociations')
            x['FunctionAssociations'].uniq{ |k| k['EventType'] }.each do |assoc|
              # What if function is not defined? - perform check
              if (assoc.has_key?('Function') and (!assoc['Function'].nil?) and (functions.keys.include? assoc['Function']))
                func_safe = assoc['Function'].gsub(/[-_.]/,"")
                assoc['EventType'] = 'viewer-request' if not assoc.has_key?('EventType')
                assoc['FunctionARN'] = FnGetAtt("#{func_safe}CloudFrontFunction", "FunctionARN")
                assoc.delete('Function') if assoc.has_key?('Function')
              else
                x['FunctionAssociations'].delete(assoc)
              end
            end
          end
        else
          config.delete(x)
        end
        if (config.length()>0)
          distribution_config[:CacheBehaviors] = config
        end
      end
    end
  end

  # Aliases
  aliases_map = external_parameters.fetch(:aliases_map, {})
  aliases = external_parameters.fetch(:aliases, [])
  if aliases_map.any?
    map = {}
    aliases_map.each { |k,v| map[k.to_sym] = { records: v.join(',') } }
    Mapping('aliases', map)
    distribution_config[:Aliases] = FnSplit(',', FnFindInMap('aliases', Ref('AliasMap'), 'records'))
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

  if (distribution_config.has_key?(:DefaultCacheBehavior) and (!distribution_config[:DefaultCacheBehavior].nil?))

    CloudFront_Distribution(:Distribution) {
      DependsOn dependencies_list
      DistributionConfig distribution_config
      Tags tags
    }

    dns_records = external_parameters.fetch(:dns_records, {})
    dns_records.each_with_index do |record, index|
      if (dns_format.to_s.start_with?('{"Fn::'))
        name = (['apex',''].include? record) ? FnJoin('', [dns_format]) : FnJoin('.', [record, dns_format])
        zone_name = FnJoin('', [dns_format, '.'])
      else
        name = (['apex',''].include? record) ? FnSub("#{dns_format}") : FnSub("#{record}.#{dns_format}")
        zone_name = FnSub("#{dns_format}.")
      end
      Route53_RecordSet("CloudfrontDns#{index}") do
        HostedZoneName zone_name
        Name name
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

end
