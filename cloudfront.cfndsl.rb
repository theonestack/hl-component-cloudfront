CloudFormation do

  Condition('WebACLEnabled', FnNot(FnEquals(Ref('WebACL'), '')))

  tags = []
  tags << { Key: 'EnvironmentName', Value: Ref('EnvironmentName') }
  tags << { Key: 'EnvironmentType', Value: Ref('EnvironmentType') }

  distribution_config = {}
  distribution_config[:Comment] = defined? decription ? decription : name
  distribution_config[:Origins] = []

  origins.each do |id,config|
    origin={
      Id: id,
      DomainName: Ref("#{id}OriginDomainName")
    }

    case config['source']
    when 'loadbalancer'

      origin[:CustomOriginConfig] = { HTTPPort: '80', HTTPSPort: '443' }
      origin[:CustomOriginConfig][:OriginKeepaliveTimeout] = config["keep_alive_timeout"] if config.has_key?('keep_alive_timeout')
      origin[:CustomOriginConfig][:OriginReadTimeout] = config["read_timeout"] if config.has_key?('read_timeout')
      origin[:CustomOriginConfig][:OriginSSLProtocols] = config['ssl_policy'] if config.has_key?('ssl_policy')
      origin[:CustomOriginConfig][:OriginProtocolPolicy] = config['protocol_policy']

    when 's3'

      CloudFront_CloudFrontOriginAccessIdentity("#{id}OriginAccessIdentity") {
        CloudFrontOriginAccessIdentityConfig({
          Comment: FnSub("${EnvironmentName}-#{id}-CloudFrontOriginAccessIdentity")
        })
      }
      origin[:S3OriginConfig] = { OriginAccessIdentity: FnSub("origin-access-identity/cloudfront/${#{id}OriginAccessIdentity}") }


    end

    distribution_config[:Origins] << origin

  end if (defined? origins) && (origins.any?)

  distribution_config[:DefaultRootObject] = default_root_object if defined? default_root_object
  distribution_config[:HttpVersion] = http_version
  distribution_config[:Enabled] = enabled
  distribution_config[:PriceClass] = Ref('PriceClass')
  distribution_config[:WebACLId] = FnIf('WebACLEnabled', Ref('WebACL'), Ref('AWS::NoValue'))

  # SSL Settings
  distribution_config[:ViewerCertificate] = {}

  case ssl['type']
  when 'acm'
    distribution_config[:ViewerCertificate][:AcmCertificateArn] = Ref('AcmCertificateArn')
  when 'iam'
    distribution_config[:ViewerCertificate][:IAMCertificateId] = Ref('IamCertificateArn')
  else
    distribution_config[:ViewerCertificate][:CloudFrontDefaultCertificate] = true
  end

  distribution_config[:ViewerCertificate][:SslSupportMethod] = ssl.has_key?('support_method') ? ssl['support_method'] : "sni-only"
  distribution_config[:ViewerCertificate][:MinimumProtocolVersion] = ssl.has_key?('minimum_protocol_version') ? ssl['minimum_protocol_version'] : "TLSv1.2_2018"

  # Cache behviours
  behaviours.each do |behaviour, config|
    if behaviour == 'default'
      distribution_config[:DefaultCacheBehavior] = config
    else
      distribution_config[:CacheBehaviors] = config
    end
  end

  # Aliases
  if (defined? aliases_map) && (aliases_map.any?)
    map = {}
    aliases_map.each { |k,v| map[k.to_sym] = { records: v.join(',') } }
    Mapping('aliases', map)
    distribution_config[:Aliases] = FnSplit(',', FnFindInMap('aliases', Ref('AliasMap'), 'records'))
  elsif (defined? aliases) && (aliases.any?)
    distribution_config[:Aliases] = aliases.map { |a| FnSub(a) }
  end

  CloudFront_Distribution(:Distribution) {
    DistributionConfig distribution_config
    Tags tags
  }

  dns_records.each_with_index do |dns, index|
    Route53_RecordSet("CloudfrontDns#{index}") do
      HostedZoneName FnSub("${DnsDomain}.")
      Name dns
      Type 'CNAME'
      TTL '60'
      ResourceRecords [FnGetAtt('Distribution', 'DomainName')]
    end
  end if defined? dns_records

  Output('DomainName') do
    Value(FnGetAtt('Distribution', 'DomainName'))
    Export FnSub("${EnvironmentName}-#{component_name}-DomainName")
  end

end
