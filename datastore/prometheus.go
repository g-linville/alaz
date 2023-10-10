package datastore

import (
	"context"
	"net/http"
	"strconv"
	"sync"

	"github.com/ddosify/alaz/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	projectLabel   = "acorn.io/project-name"
	appLabel       = "acorn.io/app-public-name"
	containerLabel = "acorn.io/container-name"
	accountIdLabel = "acorn.io/account-id"
)

type PrometheusExporter struct {
	ctx context.Context
	reg *prometheus.Registry

	latencyHistogram *prometheus.HistogramVec
	statusCounter    *prometheus.CounterVec

	podCache *eventCache
	svcCache *eventCache

	reqChanBuffer chan Request
	podEventChan  chan IEvent // *PodEvent
	svcEventChan  chan IEvent // *SvcEvent
}

type eventCache struct {
	c map[string]IEvent
	m sync.RWMutex
}

func newEventCache() *eventCache {
	return &eventCache{
		c: make(map[string]IEvent),
		m: sync.RWMutex{},
	}
}

func (c *eventCache) get(uid string) (IEvent, bool) {
	c.m.RLock()
	defer c.m.RUnlock()
	val, ok := c.c[uid]
	return val, ok
}

func (c *eventCache) set(uid string, e IEvent) {
	c.m.Lock()
	defer c.m.Unlock()
	c.c[uid] = e
}

func NewPrometheusExporter(ctx context.Context) *PrometheusExporter {
	exporter := &PrometheusExporter{
		ctx:           ctx,
		reg:           prometheus.NewRegistry(),
		podCache:      newEventCache(),
		svcCache:      newEventCache(),
		reqChanBuffer: make(chan Request, 10000),
		podEventChan:  make(chan IEvent, 100),
		svcEventChan:  make(chan IEvent, 100),
	}

	exporter.latencyHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "alaz",
			Name:      "http_latency",
			Buckets:   []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000},
		},
		[]string{"fromPod", "fromNamespace", "toPod", "toNamespace", "toHost", "toPort", "toService",
			"fromAcornProject", "fromAcornApp", "fromAcornContainer", "fromAcornAccountId",
			"toAcornProject", "toAcornApp", "toAcornContainer", "toAcornAccountId"},
	)
	exporter.reg.MustRegister(exporter.latencyHistogram)

	exporter.statusCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "alaz",
			Name:      "http_status",
		},
		[]string{"fromPod", "fromNamespace", "toPod", "toNamespace", "toHost", "toPort", "toService", "status",
			"fromAcornProject", "fromAcornApp", "fromAcornContainer", "fromAcornAccountId",
			"toAcornProject", "toAcornApp", "toAcornContainer", "toAcornAccountId"},
	)
	exporter.reg.MustRegister(exporter.statusCounter)

	// Set up caches
	go exporter.startCache(exporter.podCache, exporter.podEventChan)
	go exporter.startCache(exporter.svcCache, exporter.svcEventChan)
	go exporter.handleReqs()

	go func() {
		http.Handle("/metricz", promhttp.HandlerFor(exporter.reg, promhttp.HandlerOpts{}))
		go func() {
			if err := http.ListenAndServe(":8080", nil); err != nil {
				log.Logger.Error().Err(err).Msg("error while serving metrics")
			}
		}()
		<-exporter.ctx.Done()
		log.Logger.Info().Msg("Prometheus exporter stopped")
	}()

	return exporter
}

func (p *PrometheusExporter) startCache(cache *eventCache, ch chan IEvent) {
	for {
		select {
		case <-p.ctx.Done():
			return
		case obj := <-ch:
			cache.set(obj.GetUID(), obj)
		}
	}
}

func (p *PrometheusExporter) handleReqs() {
	for {
		select {
		case <-p.ctx.Done():
			return
		case req := <-p.reqChanBuffer:
			p.handleReq(req)
		}
	}
}

func (p *PrometheusExporter) handleReq(req Request) {
	fromPod, found := p.podCache.get(req.FromUID)
	if !found {
		log.Logger.Warn().Str("uid", req.FromUID).Msg("pod not found")
		return
	}

	switch req.ToType {
	case "pod":
		toPod, found := p.podCache.get(req.ToUID)
		if !found {
			return
		}
		p.updateMetricsToPod(fromPod.(*PodEvent), toPod.(*PodEvent), req)
	case "service":
		toSvc, found := p.svcCache.get(req.ToUID)
		if !found {
			return
		}
		p.updateMetricsToSvc(fromPod.(*PodEvent), toSvc.(*SvcEvent), req)
	case "outbound":
		p.updateMetricsToOutbound(fromPod.(*PodEvent), req)
	}
}

func (p *PrometheusExporter) updateMetricsToPod(fromPod, toPod *PodEvent, req Request) {
	p.latencyHistogram.With(prometheus.Labels{
		"fromPod":            fromPod.Name,
		"fromNamespace":      fromPod.Namespace,
		"toPod":              toPod.Name,
		"toNamespace":        toPod.Namespace,
		"toService":          "",
		"toHost":             "",
		"toPort":             strconv.Itoa(int(req.ToPort)),
		"fromAcornProject":   fromPod.Labels[projectLabel],
		"fromAcornApp":       fromPod.Labels[appLabel],
		"fromAcornContainer": fromPod.Labels[containerLabel],
		"fromAcornAccountId": fromPod.Labels[accountIdLabel],
		"toAcornProject":     toPod.Labels[projectLabel],
		"toAcornApp":         toPod.Labels[appLabel],
		"toAcornContainer":   toPod.Labels[containerLabel],
		"toAcornAccountId":   toPod.Labels[accountIdLabel],
	}).Observe(float64(req.Latency) / float64(1000000)) // divide by 1 million to convert nanoseconds to milliseconds

	p.statusCounter.With(prometheus.Labels{
		"fromPod":            fromPod.Name,
		"fromNamespace":      fromPod.Namespace,
		"toPod":              toPod.Name,
		"toNamespace":        toPod.Namespace,
		"toService":          "",
		"toHost":             "",
		"toPort":             strconv.Itoa(int(req.ToPort)),
		"status":             strconv.Itoa(int(req.StatusCode)),
		"fromAcornProject":   fromPod.Labels[projectLabel],
		"fromAcornApp":       fromPod.Labels[appLabel],
		"fromAcornContainer": fromPod.Labels[containerLabel],
		"fromAcornAccountId": fromPod.Labels[accountIdLabel],
		"toAcornProject":     toPod.Labels[projectLabel],
		"toAcornApp":         toPod.Labels[appLabel],
		"toAcornContainer":   toPod.Labels[containerLabel],
		"toAcornAccountId":   toPod.Labels[accountIdLabel],
	}).Inc()
}

func (p *PrometheusExporter) updateMetricsToSvc(fromPod *PodEvent, toSvc *SvcEvent, req Request) {
	p.latencyHistogram.With(prometheus.Labels{
		"fromPod":            fromPod.Name,
		"fromNamespace":      fromPod.Namespace,
		"toService":          toSvc.Name,
		"toNamespace":        toSvc.Namespace,
		"toPod":              "",
		"toHost":             "",
		"toPort":             strconv.Itoa(int(req.ToPort)),
		"fromAcornProject":   fromPod.Labels[projectLabel],
		"fromAcornApp":       fromPod.Labels[appLabel],
		"fromAcornContainer": fromPod.Labels[containerLabel],
		"fromAcornAccountId": fromPod.Labels[accountIdLabel],
		"toAcornProject":     "",
		"toAcornApp":         "",
		"toAcornContainer":   "",
		"toAcornAccountId":   "",
	}).Observe(float64(req.Latency) / float64(1000000)) // divide by 1 million to convert nanoseconds to milliseconds

	p.statusCounter.With(prometheus.Labels{
		"fromPod":            fromPod.Name,
		"fromNamespace":      fromPod.Namespace,
		"toService":          toSvc.Name,
		"toNamespace":        toSvc.Namespace,
		"toPod":              "",
		"toHost":             "",
		"toPort":             strconv.Itoa(int(req.ToPort)),
		"status":             strconv.Itoa(int(req.StatusCode)),
		"fromAcornProject":   fromPod.Labels[projectLabel],
		"fromAcornApp":       fromPod.Labels[appLabel],
		"fromAcornContainer": fromPod.Labels[containerLabel],
		"fromAcornAccountId": fromPod.Labels[accountIdLabel],
		"toAcornProject":     "",
		"toAcornApp":         "",
		"toAcornContainer":   "",
		"toAcornAccountId":   "",
	}).Inc()
}

func (p *PrometheusExporter) updateMetricsToOutbound(fromPod *PodEvent, req Request) {
	p.latencyHistogram.With(prometheus.Labels{
		"fromPod":            fromPod.Name,
		"fromNamespace":      fromPod.Namespace,
		"toHost":             req.ToUID, // req.ToUID is the website hostname in this case, i.e. google.com
		"toService":          "",
		"toPod":              "",
		"toNamespace":        "",
		"toPort":             strconv.Itoa(int(req.ToPort)),
		"fromAcornProject":   fromPod.Labels[projectLabel],
		"fromAcornApp":       fromPod.Labels[appLabel],
		"fromAcornContainer": fromPod.Labels[containerLabel],
		"fromAcornAccountId": fromPod.Labels[accountIdLabel],
		"toAcornProject":     "",
		"toAcornApp":         "",
		"toAcornContainer":   "",
		"toAcornAccountId":   "",
	}).Observe(float64(req.Latency) / float64(1000000)) // divide by 1 million to convert nanoseconds to milliseconds

	p.statusCounter.With(prometheus.Labels{
		"fromPod":            fromPod.Name,
		"fromNamespace":      fromPod.Namespace,
		"toHost":             req.ToUID, // req.ToUID is the website hostname in this case, i.e. google.com
		"toService":          "",
		"toPod":              "",
		"toNamespace":        "",
		"toPort":             strconv.Itoa(int(req.ToPort)),
		"status":             strconv.Itoa(int(req.StatusCode)),
		"fromAcornProject":   fromPod.Labels[projectLabel],
		"fromAcornApp":       fromPod.Labels[appLabel],
		"fromAcornContainer": fromPod.Labels[containerLabel],
		"fromAcornAccountId": fromPod.Labels[accountIdLabel],
		"toAcornProject":     "",
		"toAcornApp":         "",
		"toAcornContainer":   "",
		"toAcornAccountId":   "",
	}).Inc()
}

func (p *PrometheusExporter) PersistRequest(request Request) error {
	p.reqChanBuffer <- request
	return nil
}

func (p *PrometheusExporter) PersistPod(pod Pod, eventType string) error {
	podEvent := convertPodToPodEvent(pod, eventType)
	p.podEventChan <- &podEvent
	return nil
}

func (p *PrometheusExporter) PersistService(service Service, eventType string) error {
	svcEvent := convertSvcToSvcEvent(service, eventType)
	p.svcEventChan <- &svcEvent
	return nil
}

func (p *PrometheusExporter) PersistDeployment(_ Deployment, _ string) error {
	// ignore
	return nil
}

func (p *PrometheusExporter) PersistReplicaSet(_ ReplicaSet, _ string) error {
	// ignore
	return nil
}

func (p *PrometheusExporter) PersistEndpoints(_ Endpoints, _ string) error {
	// ignore
	return nil
}

func (p *PrometheusExporter) PersistDaemonSet(_ DaemonSet, _ string) error {
	// ignore
	return nil
}

func (p *PrometheusExporter) PersistContainer(_ Container, _ string) error {
	// ignore
	return nil
}
