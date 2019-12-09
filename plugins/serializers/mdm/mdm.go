package mdm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/influxdata/telegraf"
)

type serializer struct {
	TimestampUnits time.Duration
}

type MDMDimension struct {
	Name  string `json:"DimensionName"`
	Value string `json:"DimensionValue"`
}

type MDMMetric struct {
	MDMtype       string         `json:"type"`
	Name          string         `json:"MetricName"`
	Value         interface{}    `json:"value"`
	MDMDimensions []MDMDimension `json:"dimensions"`
}

type MDMMetrics []MDMMetric

var MDMtypeValues = map[string]string{
	"connect":    "ConnectedClusterAgent",
	"controller": "ControllerManager",
	"config":     "ConfigAgent",
}

func NewSerializer() (*serializer, error) {
	s := &serializer{}
	return s, nil
}

func (s *serializer) Serialize(metric telegraf.Metric) ([]byte, error) {

	m, err := s.createObject(metric)
	if err != nil {
		return nil, fmt.Errorf("D! [serializer.mdmmetric] Dropping invalid metric: %s", metric.Name())
	}

	return m, nil
}

func (s *serializer) SerializeBatch(metrics []telegraf.Metric) ([]byte, error) {
	objects := make([]byte, 0)
	for _, metric := range metrics {
		m, err := s.createObject(metric)
		if err != nil {
			return nil, fmt.Errorf("D! [serializer.mdmmetric] Dropping invalid metric: %s", metric.Name())
		} else if m != nil {
			objects = append(objects, m...)
		}
	}
	replaced := bytes.Replace(objects, []byte("]["), []byte(","), -1)
	return replaced, nil
}

func (s *serializer) createObject(metric telegraf.Metric) ([]byte, error) {
	var allMetrics MDMMetrics
	var mdmmetric MDMMetric
	mdmmetric.Name = metric.Name()

	for _, field := range metric.FieldList() {
		if !verifyValue(field.Value) {
			// Ignore String
			continue
		}

		if field.Key == "" {
			// Ignore Empty Key
			continue
		}
		mdmmetric.Value = field.Value
	}

	mdmmetric.MDMtype = MDMtypeValues[metric.Tags()["service"]]
	allMetrics = append(allMetrics, mdmmetric)
	metricsJSON, _ := json.Marshal(allMetrics)
	return metricsJSON, nil
}

func verifyValue(v interface{}) bool {
	switch v.(type) {
	case string:
		return false
	}
	return true
}
