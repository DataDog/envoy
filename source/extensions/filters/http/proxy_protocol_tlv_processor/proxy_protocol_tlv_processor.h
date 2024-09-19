#pragma once

#include <string>

#include "envoy/extensions/filters/http/proxy_protocol_tlv_processor/v3/proxy_protocol_tlv_processor.pb.h"

#include "source/extensions/filters/http/common/pass_through_filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ProxyProtocolTlvProcessor {

class FilterConfig {
public:
  FilterConfig(const envoy::extensions::filters::http::proxy_protocol_tlv_processor::v3::
                   ProxyProtocolTlvProcessor& proto_config);

  const absl::flat_hash_set<uint32_t>& tlvs() const { return tlvs_; }
  const std::string& headerPrefix() const { return header_prefix_; }
  const std::string& metadataNamespace() const { return metadata_namespace_; }
  bool shouldSetHeaders() const { return set_headers_; }
  bool shouldSetMetadata() const { return set_metadata_; }

private:
  absl::flat_hash_set<uint32_t> tlvs_;
  std::string header_prefix_;
  std::string metadata_namespace_;
  bool set_headers_;
  bool set_metadata_;
};

class ProxyProtocolTlvProcessorFilter : public Http::PassThroughFilter {
public:
  friend class ProxyProtoTlvProcesserTest;

  ProxyProtocolTlvProcessorFilter(std::shared_ptr<FilterConfig> config);

  virtual ~ProxyProtocolTlvProcessorFilter() {}

  void onDestroy() override {}

  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap&, bool) override;
  Http::FilterDataStatus decodeData(Buffer::Instance&, bool) override {
    return Envoy::Http::FilterDataStatus::Continue;
  }
  Http::FilterHeadersStatus encodeHeaders(Http::ResponseHeaderMap&, bool) override {
    return Envoy::Http::FilterHeadersStatus::Continue;
  }
  Http::FilterDataStatus encodeData(Buffer::Instance&, bool) override {
    return Envoy::Http::FilterDataStatus::Continue;
  }

private:
  virtual const Network::ProxyProtocolData& getProxyProtocolData() const;
  virtual bool doesProxyProtoDataExist() const;

  std::shared_ptr<FilterConfig> config_;
};
} // namespace ProxyProtocolTlvProcessor
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
