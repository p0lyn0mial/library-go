package manifestclient

import (
	"embed"
	"fmt"
	"io/fs"
	"sync"

	apidiscoveryv2 "k8s.io/api/apidiscovery/v2"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/json"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
)

type kindData struct {
	kind     schema.GroupVersionKind
	listKind schema.GroupVersionKind
	err      error
}

func newDiscoveryReader(content fs.FS) *discoveryReader {
	return &discoveryReader{
		sourceFS:        content,
		kindForResource: make(map[schema.GroupVersionResource]kindData),
	}
}

type discoveryReader struct {
	kindForResource map[schema.GroupVersionResource]kindData

	sourceFS fs.FS
	lock     sync.RWMutex
}

func (dr *discoveryReader) getKindForResource(gvr schema.GroupVersionResource) (kindData, error) {
	dr.lock.RLock()
	kindForGVR, ok := dr.kindForResource[gvr]
	if ok {
		defer dr.lock.RUnlock()
		return kindForGVR, kindForGVR.err
	}
	dr.lock.RUnlock()

	dr.lock.Lock()
	defer dr.lock.Unlock()

	kindForGVR, ok = dr.kindForResource[gvr]
	if ok {
		return kindForGVR, kindForGVR.err
	}

	discoveryPath := "/apis"
	if len(gvr.Group) == 0 {
		discoveryPath = "/api"
	}
	discoveryBytes, err := dr.getGroupResourceDiscovery(&apirequest.RequestInfo{Path: discoveryPath})
	if err != nil {
		kindForGVR.err = fmt.Errorf("error reading discovery: %w", err)
		dr.kindForResource[gvr] = kindForGVR
		return kindForGVR, kindForGVR.err
	}

	discoveryInfo := &apidiscoveryv2.APIGroupDiscoveryList{}
	if err := json.Unmarshal(discoveryBytes, discoveryInfo); err != nil {
		kindForGVR.err = fmt.Errorf("error unmarshalling discovery: %w", err)
		dr.kindForResource[gvr] = kindForGVR
		return kindForGVR, kindForGVR.err
	}

	kindForGVR.err = fmt.Errorf("did not find kind for %v\n", gvr)
	for _, groupInfo := range discoveryInfo.Items {
		if groupInfo.Name != gvr.Group {
			continue
		}
		for _, versionInfo := range groupInfo.Versions {
			if versionInfo.Version != gvr.Version {
				continue
			}
			for _, resourceInfo := range versionInfo.Resources {
				if resourceInfo.Resource != gvr.Resource {
					continue
				}
				if resourceInfo.ResponseKind == nil {
					continue
				}
				kindForGVR.kind = schema.GroupVersionKind{
					Group:   gvr.Group,
					Version: gvr.Version,
					Kind:    resourceInfo.ResponseKind.Kind,
				}
				if len(resourceInfo.ResponseKind.Group) > 0 {
					kindForGVR.kind.Group = resourceInfo.ResponseKind.Group
				}
				if len(resourceInfo.ResponseKind.Version) > 0 {
					kindForGVR.kind.Version = resourceInfo.ResponseKind.Version
				}
				kindForGVR.listKind = schema.GroupVersionKind{
					Group:   kindForGVR.kind.Group,
					Version: kindForGVR.kind.Version,
					Kind:    resourceInfo.ResponseKind.Kind + "List",
				}
				kindForGVR.err = nil
				dr.kindForResource[gvr] = kindForGVR
				return kindForGVR, kindForGVR.err
			}
		}
	}

	dr.kindForResource[gvr] = kindForGVR
	return kindForGVR, kindForGVR.err
}

//go:embed default-discovery
var defaultDiscovery embed.FS
