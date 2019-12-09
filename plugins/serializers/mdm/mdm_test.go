package mdm

import (
	"fmt"
	"testing"
	"time"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/metric"
	"github.com/stretchr/testify/assert"
)

func MustMetric(v telegraf.Metric, err error) telegraf.Metric {
	if err != nil {
		panic(err)
	}
	return v
}

func TestSerializeMetricInt(t *testing.T) {
	now := time.Now()
	tags := map[string]string{
		"service": "connect",
		"cpu":     "cpu0",
	}
	fields := map[string]interface{}{
		"counter": int64(90),
	}
	m, err := metric.New("process_uptime_seconds", tags, fields, now)
	assert.NoError(t, err)

	s, _ := NewSerializer()
	var buf []byte
	buf, err = s.Serialize(m)
	assert.NoError(t, err)

	expS := []byte(fmt.Sprintf(`[{"type":"ConnectedClusterAgent","MetricName":"process_uptime_seconds","value":90,"dimensions":null}]`))
	assert.Equal(t, string(expS), string(buf))
}

func TestSerializeBatchMetricInt(t *testing.T) {
	now := time.Now()
	tags := map[string]string{
		"service": "connect",
		"cpu":     "cpu0",
	}
	fields := map[string]interface{}{
		"counter": int64(90),
	}
	m, err := metric.New("process_uptime_seconds", tags, fields, now)
	m2, err := metric.New("process_resident_memory_bytes", tags, fields, now)
	m3, err := metric.New("process_cpu_seconds_total", tags, fields, now)
	assert.NoError(t, err)

	metrics := []telegraf.Metric{
		m, m2, m3,
	}
	s, _ := NewSerializer()
	var buf []byte
	buf, err = s.SerializeBatch(metrics)
	assert.NoError(t, err)

	expS := []byte(fmt.Sprintf(`[{"type":"ConnectedClusterAgent","MetricName":"process_uptime_seconds","value":90,"dimensions":null},{"type":"ConnectedClusterAgent","MetricName":"process_resident_memory_bytes","value":90,"dimensions":null},{"type":"ConnectedClusterAgent","MetricName":"process_cpu_seconds_total","value":90,"dimensions":null}]`))
	assert.Equal(t, string(expS), string(buf))
}
