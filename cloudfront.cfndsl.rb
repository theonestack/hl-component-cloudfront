CloudFormation do

  Condition('WebACLEnabled', FnNot(FnEquals(Ref('WebACL'), '')))
  Condition('OverrideAliases', FnNot(FnEquals(Ref('OverrideAliases'), '')))
  Condition('EnableLambdaFunctionAssociations', FnEquals(Ref('EnableLambdaFunctionAssociations'), 'true'))

  tags = []
  tags << { Key: 'Environment', Value: Ref('EnvironmentName') }
  tags << { Key: 'EnvironmentType', Value: Ref('EnvironmentType') }

  distribution_config = {}
  distribution_config[:Comment] = FnSub(comment)
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
      Condition("#{id}CreateOriginAccessIdentity", FnEquals(Ref("#{id}OriginAccessIdentityInput"), ''))

      CloudFront_CloudFrontOriginAccessIdentity("#{id}OriginAccessIdentity") {
        Condition("#{id}CreateOriginAccessIdentity")
        CloudFrontOriginAccessIdentityConfig({
          Comment: FnSub("${EnvironmentName}-#{id}-CloudFrontOriginAccessIdentity")
        })
      }
      origin[:S3OriginConfig] = { OriginAccessIdentity: 
        FnIf("#{id}CreateOriginAccessIdentity",
          FnSub("origin-access-identity/cloudfront/${#{id}OriginAccessIdentity}"),
          FnSub("origin-access-identity/cloudfront/${#{id}OriginAccessIdentityInput}")
        )
      }

      Output("#{id}OriginAccessIdentity") do
        Condition("#{id}CreateOriginAccessIdentity")
        Value(FnGetAtt("#{id}OriginAccessIdentity", 'S3CanonicalUserId'))
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

  # Cache behviours
  behaviours = external_parameters.fetch(:behaviours, {})
  behaviours.each do |behaviour, config|
    if behaviour == 'default'
      distribution_config[:DefaultCacheBehavior] = config
    else
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

  CloudFront_Distribution(:Distribution) {
    DistributionConfig distribution_config
    Tags tags
  }

  dns_records = external_parameters.fetch(:dns_records, {})
  dns_records.each_with_index do |record, index|
    name = (['apex',''].include? record) ? dns_format : "#{record}.#{dns_format}."
    Route53_RecordSet("CloudfrontDns#{index}") do
      HostedZoneName FnSub("#{dns_format}.")
      Name FnSub(name)
      Type 'A'
      AliasTarget ({
          DNSName: FnGetAtt(:Distribution, :DomainName),
          HostedZoneId: 'Z2FDTNDATAQYW2'
      })
    end
  end

  Output('DomainName') do
    Value(FnGetAtt('Distribution', 'DomainName'))
    Export FnSub("${EnvironmentName}-#{external_parameters[:export_name]}-DomainName")
  end

  Output('DistributionId') do
    Value(FnGetAtt('Distribution', 'Id'))
    Export FnSub("${EnvironmentName}-#{external_parameters[:export_name]}-DistributionId")
  end

end
