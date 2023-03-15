#include "envoy/tracing/trace_reason.h"

#include "source/common/tracing/null_span_impl.h"
#include "source/extensions/tracers/datadog/tracer.h"

#include "test/mocks/thread_local/mocks.h"
#include "test/mocks/upstream/cluster_manager.h"
#include "test/test_common/simulated_time_system.h"
#include "test/test_common/utility.h"

#include "datadog/error.h"
#include "datadog/expected.h"
#include "datadog/tracer_config.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace Tracers {
namespace Datadog {
namespace {

class DatadogTracerTest : public testing::Test {
public:
  DatadogTracerTest() {
    cluster_manager_.initializeClusters({"fake_cluster"}, {});
    cluster_manager_.thread_local_cluster_.cluster_.info_->name_ = "fake_cluster";
    cluster_manager_.initializeThreadLocalClusters({"fake_cluster"});
  }

protected:
  NiceMock<Upstream::MockClusterManager> cluster_manager_;
  Stats::TestUtil::TestStore store_;
  NiceMock<ThreadLocal::MockInstance> thread_local_slot_allocator_;
  Event::SimulatedTimeSystem time_;
};

TEST_F(DatadogTracerTest, Breathing) {
  // Verify that constructing a `Tracer` instance with mocked dependencies
  // does not throw exceptions.
  datadog::tracing::TracerConfig config;
  config.defaults.service = "envoy";

  Tracer tracer("fake_cluster", "test_host", config, cluster_manager_, *store_.rootScope(),
                thread_local_slot_allocator_);

  (void)tracer;
}

TEST_F(DatadogTracerTest, NoOpMode) {
  // Verify that when the tracer fails to validate its configuration,
  // `startSpan` subsequently returns `NullSpan` instances.
  datadog::tracing::TracerConfig config;
  config.defaults.service = "envoy";
  datadog::tracing::TraceSamplerConfig::Rule invalid_rule;
  // The `sample_rate`, below, is invalid (should be between 0.0 and 1.0).
  // As a result, the constructor of `Tracer` will fail to initialize the
  // underlying `datadog::tracing::Tracer`, and instead go into a no-op mode
  // where `startSpan` returns `NullSpan` instances.
  invalid_rule.sample_rate = -10;
  config.trace_sampler.rules.push_back(invalid_rule);

  Tracer tracer("fake_cluster", "test_host", config, cluster_manager_, *store_.rootScope(),
                thread_local_slot_allocator_);

  Tracing::TestTraceContextImpl context{};
  // Any values will do for the sake of this test.
  Tracing::Decision decision;
  decision.reason = Tracing::Reason::Sampling;
  decision.traced = true;

  const Tracing::SpanPtr span = tracer.startSpan(Tracing::MockConfig{}, context, "do.thing",
                                                 time_.timeSystem().systemTime(), decision);
  ASSERT_TRUE(span);
  const auto as_null_span = dynamic_cast<Tracing::NullSpan*>(span.get());
  EXPECT_NE(nullptr, as_null_span);
}

} // namespace
} // namespace Datadog
} // namespace Tracers
} // namespace Extensions
} // namespace Envoy
