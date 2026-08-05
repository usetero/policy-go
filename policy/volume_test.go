package policy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// Volume is counted for every record entering evaluation, including when no
// policies are loaded at all.
func TestVolume_CountsRecordsWithNoPolicies(t *testing.T) {
	registry := NewPolicyRegistry()
	e := NewPolicyEngine(registry)

	EvaluateLog(e, &SimpleLogRecord{Body: []byte("hi")}, SimpleLogOptions()...)
	EvaluateLog(e, &SimpleLogRecord{Body: []byte("there")}, SimpleLogOptions()...)
	EvaluateMetric(e, &SimpleMetricRecord{Name: []byte("m")}, SimpleMetricOptions()...)
	EvaluateTrace(e, &SimpleSpanRecord{Name: []byte("s")}, SimpleSpanOptions()...)

	snap := registry.CollectVolume()
	assert.Equal(t, int64(2), snap.LogRecords)
	assert.Equal(t, int64(1), snap.MetricDataPoints)
	assert.Equal(t, int64(1), snap.Spans)
	assert.Zero(t, snap.LogBytes, "bytes are opt-in")

	// Snapshot resets: the next collect is the delta since this one.
	assert.True(t, registry.CollectVolume().IsZero())
}

func TestVolume_BytesAreOptIn(t *testing.T) {
	registry := NewPolicyRegistry()
	registry.AddLogBytes(120)
	registry.AddLogBytes(30)
	registry.AddMetricBytes(7)
	registry.AddSpanBytes(9)

	snap := registry.CollectVolume()
	assert.Equal(t, int64(150), snap.LogBytes)
	assert.Equal(t, int64(7), snap.MetricBytes)
	assert.Equal(t, int64(9), snap.SpanBytes)
	assert.Zero(t, snap.LogRecords)
}

// Registering a provider wires the volume collector, so sync requests carry
// volume without the consumer doing anything.
func TestVolume_HttpProviderReportsAndResetsOnSuccess(t *testing.T) {
	var requests []*policyv1.VolumeStats
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req policyv1.SyncRequest
		require.NoError(t, proto.Unmarshal(body, &req))
		requests = append(requests, req.GetVolume())

		out, _ := proto.Marshal(&policyv1.SyncResponse{Hash: "test"})
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.Write(out)
	}))
	defer server.Close()

	registry := NewPolicyRegistry()
	p := NewHttpProvider(server.URL, WithContentType(ContentTypeProtobuf))
	handle, err := registry.Register(p)
	require.NoError(t, err)
	defer handle.Unregister()

	// Register triggers an initial sync with nothing observed yet: a zero-valued
	// message is omitted rather than sent.
	require.Len(t, requests, 1)
	assert.Nil(t, requests[0])

	e := NewPolicyEngine(registry)
	EvaluateLog(e, &SimpleLogRecord{Body: []byte("hi")}, SimpleLogOptions()...)
	registry.AddLogBytes(64)

	_, err = p.Load()
	require.NoError(t, err)
	require.Len(t, requests, 2)
	assert.Equal(t, int64(1), requests[1].GetLogRecords())
	assert.Equal(t, int64(64), requests[1].GetLogBytes())

	// The successful sync cleared the counters.
	_, err = p.Load()
	require.NoError(t, err)
	require.Len(t, requests, 3)
	assert.Nil(t, requests[2])
}

// Every way a sync can fail must hand the drained volume back, including a 200
// response that is undecodable or carries an error_message — those paths return
// after the request is already on the wire.
func TestVolume_HttpProviderRetainsVolumeOnFailure(t *testing.T) {
	writeOK := func(w http.ResponseWriter) {
		out, _ := proto.Marshal(&policyv1.SyncResponse{Hash: "test"})
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.Write(out)
	}

	failures := map[string]func(w http.ResponseWriter){
		"transport error": func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusInternalServerError)
		},
		"undecodable 200": func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/x-protobuf")
			w.Write([]byte{0xff, 0xff, 0xff, 0xff})
		},
		"200 with error_message": func(w http.ResponseWriter) {
			out, _ := proto.Marshal(&policyv1.SyncResponse{ErrorMessage: "boom"})
			w.Header().Set("Content-Type", "application/x-protobuf")
			w.Write(out)
		},
	}

	for name, writeFailure := range failures {
		t.Run(name, func(t *testing.T) {
			var requests []*policyv1.VolumeStats
			fail := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				var req policyv1.SyncRequest
				require.NoError(t, proto.Unmarshal(body, &req))
				requests = append(requests, req.GetVolume())

				if fail {
					writeFailure(w)
					return
				}
				writeOK(w)
			}))
			defer server.Close()

			registry := NewPolicyRegistry()
			p := NewHttpProvider(server.URL, WithContentType(ContentTypeProtobuf))
			handle, err := registry.Register(p)
			require.NoError(t, err)
			defer handle.Unregister()
			require.Len(t, requests, 1)

			e := NewPolicyEngine(registry)
			EvaluateLog(e, &SimpleLogRecord{Body: []byte("hi")}, SimpleLogOptions()...)
			registry.AddLogBytes(64)

			// The failing sync reports the volume but must not consume it.
			fail = true
			_, err = p.Load()
			require.Error(t, err)
			require.Len(t, requests, 2)
			assert.Equal(t, int64(1), requests[1].GetLogRecords())
			assert.Equal(t, int64(64), requests[1].GetLogBytes())

			// Next attempt reports the retained counters plus anything new.
			EvaluateLog(e, &SimpleLogRecord{Body: []byte("again")}, SimpleLogOptions()...)
			fail = false
			_, err = p.Load()
			require.NoError(t, err)
			require.Len(t, requests, 3)
			assert.Equal(t, int64(2), requests[2].GetLogRecords())
			assert.Equal(t, int64(64), requests[2].GetLogBytes())
		})
	}
}

func TestVolume_GrpcProviderReportsVolume(t *testing.T) {
	server := &mockPolicyServer{}
	server.setHandler(func(ctx context.Context, req *policyv1.SyncRequest) (*policyv1.SyncResponse, error) {
		return &policyv1.SyncResponse{Hash: "test"}, nil
	})
	addr, cleanup := startTestServer(t, server)
	defer cleanup()

	registry := NewPolicyRegistry()
	p := NewGrpcProvider(addr, WithGrpcInsecure(), WithGrpcPollInterval(0))
	handle, err := registry.Register(p)
	require.NoError(t, err)
	defer handle.Unregister()
	defer p.Stop()

	e := NewPolicyEngine(registry)
	EvaluateTrace(e, &SimpleSpanRecord{Name: []byte("s")}, SimpleSpanOptions()...)
	registry.AddSpanBytes(11)

	_, err = p.Load()
	require.NoError(t, err)

	vol := server.getLastRequest().GetVolume()
	assert.Equal(t, int64(1), vol.GetSpans())
	assert.Equal(t, int64(11), vol.GetSpanBytes())
}

func TestVolume_GrpcProviderRetainsVolumeOnFailure(t *testing.T) {
	failures := map[string]func() (*policyv1.SyncResponse, error){
		"rpc error": func() (*policyv1.SyncResponse, error) {
			return nil, errors.New("unavailable")
		},
		"error_message": func() (*policyv1.SyncResponse, error) {
			return &policyv1.SyncResponse{ErrorMessage: "boom"}, nil
		},
	}

	for name, failure := range failures {
		t.Run(name, func(t *testing.T) {
			fail := false
			server := &mockPolicyServer{}
			server.setHandler(func(ctx context.Context, req *policyv1.SyncRequest) (*policyv1.SyncResponse, error) {
				if fail {
					return failure()
				}
				return &policyv1.SyncResponse{Hash: "test"}, nil
			})
			addr, cleanup := startTestServer(t, server)
			defer cleanup()

			registry := NewPolicyRegistry()
			p := NewGrpcProvider(addr, WithGrpcInsecure(), WithGrpcPollInterval(0))
			handle, err := registry.Register(p)
			require.NoError(t, err)
			defer handle.Unregister()
			defer p.Stop()

			e := NewPolicyEngine(registry)
			EvaluateTrace(e, &SimpleSpanRecord{Name: []byte("s")}, SimpleSpanOptions()...)
			registry.AddSpanBytes(11)

			fail = true
			_, err = p.Load()
			require.Error(t, err)
			vol := server.getLastRequest().GetVolume()
			assert.Equal(t, int64(1), vol.GetSpans())
			assert.Equal(t, int64(11), vol.GetSpanBytes())

			// Next attempt reports the retained counters plus anything new.
			EvaluateTrace(e, &SimpleSpanRecord{Name: []byte("s2")}, SimpleSpanOptions()...)
			fail = false
			_, err = p.Load()
			require.NoError(t, err)
			vol = server.getLastRequest().GetVolume()
			assert.Equal(t, int64(2), vol.GetSpans())
			assert.Equal(t, int64(11), vol.GetSpanBytes())
		})
	}
}

// Overlapping syncs each drain a disjoint delta, so the total reported across
// all requests is exactly what was observed — no double counting, no loss.
func TestVolume_ConcurrentSyncsDoNotDoubleCount(t *testing.T) {
	const records = 200

	var mu sync.Mutex
	var reported int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req policyv1.SyncRequest
		require.NoError(t, proto.Unmarshal(body, &req))
		mu.Lock()
		reported += req.GetVolume().GetLogRecords()
		mu.Unlock()

		out, _ := proto.Marshal(&policyv1.SyncResponse{Hash: "test"})
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.Write(out)
	}))
	defer server.Close()

	registry := NewPolicyRegistry()
	p := NewHttpProvider(server.URL, WithContentType(ContentTypeProtobuf))
	handle, err := registry.Register(p)
	require.NoError(t, err)
	defer handle.Unregister()

	e := NewPolicyEngine(registry)
	for range records {
		EvaluateLog(e, &SimpleLogRecord{Body: []byte("hi")}, SimpleLogOptions()...)
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := p.Load()
			assert.NoError(t, err)
		}()
	}
	wg.Wait()

	// Whatever wasn't drained by a sync is still on the registry's counters.
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, int64(records), reported+registry.CollectVolume().LogRecords)
}

// A provider that doesn't implement SetVolumeReporter still registers fine.
func TestVolume_ProviderWithoutVolumeSupport(t *testing.T) {
	registry := NewPolicyRegistry()
	handle, err := registry.Register(newStaticProvider(nil))
	require.NoError(t, err)
	handle.Unregister()
}
