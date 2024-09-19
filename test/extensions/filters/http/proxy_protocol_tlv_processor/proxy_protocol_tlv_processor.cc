#include "source/common/common/base64.h"
#include "source/common/network/address_impl.h"
#include "source/extensions/filters/http/proxy_protocol_tlv_processor/proxy_protocol_tlv_processor.h"
#include "source/extensions/filters/http/well_known_names.h"

#include "test/mocks/http/mocks.h"
#include "test/mocks/network/mocks.h"
#include "test/mocks/server/factory_context.h"
#include "test/test_common/printers.h"
#include "test/test_common/test_runtime.h"
#include "test/test_common/utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::_;
using testing::NiceMock;
using testing::Return;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ProxyProtocolTlvProcessor {
namespace {

class ProxyProtocolTlvProcessorFilterMock : public ProxyProtocolTlvProcessorFilter {
public:
  ProxyProtocolTlvProcessorFilterMock(std::shared_ptr<FilterConfig> config)
      : ProxyProtocolTlvProcessorFilter(config) {}
  MOCK_METHOD(const Network::ProxyProtocolData&, getProxyProtocolData, (), (const, override));
  MOCK_METHOD(bool, doesProxyProtoDataExist, (), (const, override));
  using ProxyProtocolTlvProcessorFilter::setDecoderFilterCallbacks;
};

struct TestParam {
  int tlv;
  bool set_headers;
  bool set_metadata;
  std::string header_prefix;
  std::string metadata_namespace;
};

class BaseTest : public testing::TestWithParam<TestParam> {
public:
  BaseTest() = default;

  void setup(std::shared_ptr<FilterConfig> config) {
    config_ = config;
    filter_ = std::make_unique<NiceMock<ProxyProtocolTlvProcessorFilterMock>>(config_);

    EXPECT_CALL(callbacks_, streamInfo()).WillRepeatedly(ReturnRef(req_info_));
    filter_->setDecoderFilterCallbacks(callbacks_);
  }

  Http::FilterHeadersStatus decodeHeaders() { return filter_->decodeHeaders(headers_, false); }

  std::shared_ptr<FilterConfig> config_;
  std::unique_ptr<NiceMock<ProxyProtocolTlvProcessorFilterMock>> filter_;
  NiceMock<Http::MockStreamDecoderFilterCallbacks> callbacks_;
  NiceMock<Envoy::StreamInfo::MockStreamInfo> req_info_;
  Http::TestRequestHeaderMapImpl headers_;
};

TEST_P(BaseTest, MetadataAndHeadersSet) {
  uint8_t tlv = 234;
  auto params = GetParam();
  envoy::extensions::filters::http::proxy_protocol_tlv_processor::v3::ProxyProtocolTlvProcessor
      api_config;
  api_config.add_tlvs(params.tlv);
  api_config.set_set_headers(params.set_headers);
  api_config.set_set_metadata(params.set_metadata);
  api_config.set_header_prefix(params.header_prefix);
  api_config.set_metadata_namespace(params.metadata_namespace);
  auto config = std::make_shared<FilterConfig>(api_config);
  setup(config);

  EXPECT_CALL(*(filter_.get()), doesProxyProtoDataExist()).WillRepeatedly(Return(true));
  auto src_addr =
      Network::Address::InstanceConstSharedPtr(new Network::Address::Ipv4Instance("1.2.3.4", 773));
  auto dst_addr =
      Network::Address::InstanceConstSharedPtr(new Network::Address::Ipv4Instance("0.1.1.2", 513));
  auto proxy_proto_data = Network::ProxyProtocolData{
      src_addr, dst_addr, {Network::ProxyProtocolTLV{tlv, {0x01, 't', 'e', 's', 't'}}}};
  EXPECT_CALL(*(filter_.get()), getProxyProtocolData())
      .WillRepeatedly(testing::ReturnRef(proxy_proto_data));
  if (params.set_metadata && params.tlv == tlv) {
    std::string space = params.metadata_namespace.empty()
                            ? HttpFilterNames::get().ProxyProtocolTlvProcessor
                            : params.metadata_namespace;
    EXPECT_CALL(req_info_, setDynamicMetadata(space, _));
    EXPECT_CALL(req_info_, setDynamicTypedMetadata(space, _));
  } else {
    EXPECT_CALL(req_info_, setDynamicMetadata(_, _)).Times(0);
    EXPECT_CALL(req_info_, setDynamicTypedMetadata(_, _)).Times(0);
  }
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, decodeHeaders());
  std::string prefix = params.header_prefix.empty() ? "ppv2_tlv_" : params.header_prefix;
  if (params.set_headers && params.tlv == tlv) {
    EXPECT_EQ(Base64::decode(headers_.get(Http::LowerCaseString(prefix + std::to_string(tlv)))[0]
                                 ->value()
                                 .getStringView()),
              "!test");
  } else {
    EXPECT_FALSE(headers_.has(Http::LowerCaseString(prefix + std::to_string(tlv))));
  }
}

std::vector<TestParam> kTests = {
    TestParam{234, true, true, "prefix", "space"},   // All enabled
    TestParam{235, true, true, "prefix", "space"},   // no tlv matches
    TestParam{234, false, true, "prefix", "space"},  // headers disabled
    TestParam{234, true, false, "prefix", "space"},  // metadata disabled
    TestParam{234, false, false, "prefix", "space"}, // NOOP
    TestParam{234, true, true, "", ""}};             // default namespace and header prefix
INSTANTIATE_TEST_SUITE_P(ProxyProtoTlvProcesser, BaseTest, testing::ValuesIn(kTests));

TEST_F(BaseTest, NoProxyProtoDataAvailable) {
  envoy::extensions::filters::http::proxy_protocol_tlv_processor::v3::ProxyProtocolTlvProcessor
      api_config;
  api_config.add_tlvs(234);
  api_config.set_set_headers(true);
  api_config.set_set_metadata(true);
  auto config = std::make_shared<FilterConfig>(api_config);
  setup(config);

  EXPECT_CALL(*(filter_.get()), doesProxyProtoDataExist()).WillRepeatedly(Return(false));
  EXPECT_CALL(*(filter_.get()), getProxyProtocolData()).Times(0);
  EXPECT_CALL(req_info_, setDynamicMetadata(_, _)).Times(0);
  EXPECT_CALL(req_info_, setDynamicTypedMetadata(_, _)).Times(0);
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, decodeHeaders());
}

} // namespace
} // namespace ProxyProtocolTlvProcessor
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
