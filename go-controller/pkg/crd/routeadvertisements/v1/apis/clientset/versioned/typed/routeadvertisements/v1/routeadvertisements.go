/*


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
// Code generated by client-gen. DO NOT EDIT.

package v1

import (
	"context"
	json "encoding/json"
	"fmt"
	"time"

	v1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/routeadvertisements/v1"
	routeadvertisementsv1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/routeadvertisements/v1/apis/applyconfiguration/routeadvertisements/v1"
	scheme "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/routeadvertisements/v1/apis/clientset/versioned/scheme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// RouteAdvertisementsGetter has a method to return a RouteAdvertisementsInterface.
// A group's client should implement this interface.
type RouteAdvertisementsGetter interface {
	RouteAdvertisements() RouteAdvertisementsInterface
}

// RouteAdvertisementsInterface has methods to work with RouteAdvertisements resources.
type RouteAdvertisementsInterface interface {
	Create(ctx context.Context, routeAdvertisements *v1.RouteAdvertisements, opts metav1.CreateOptions) (*v1.RouteAdvertisements, error)
	Update(ctx context.Context, routeAdvertisements *v1.RouteAdvertisements, opts metav1.UpdateOptions) (*v1.RouteAdvertisements, error)
	UpdateStatus(ctx context.Context, routeAdvertisements *v1.RouteAdvertisements, opts metav1.UpdateOptions) (*v1.RouteAdvertisements, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*v1.RouteAdvertisements, error)
	List(ctx context.Context, opts metav1.ListOptions) (*v1.RouteAdvertisementsList, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.RouteAdvertisements, err error)
	Apply(ctx context.Context, routeAdvertisements *routeadvertisementsv1.RouteAdvertisementsApplyConfiguration, opts metav1.ApplyOptions) (result *v1.RouteAdvertisements, err error)
	ApplyStatus(ctx context.Context, routeAdvertisements *routeadvertisementsv1.RouteAdvertisementsApplyConfiguration, opts metav1.ApplyOptions) (result *v1.RouteAdvertisements, err error)
	RouteAdvertisementsExpansion
}

// routeAdvertisements implements RouteAdvertisementsInterface
type routeAdvertisements struct {
	client rest.Interface
}

// newRouteAdvertisements returns a RouteAdvertisements
func newRouteAdvertisements(c *K8sV1Client) *routeAdvertisements {
	return &routeAdvertisements{
		client: c.RESTClient(),
	}
}

// Get takes name of the routeAdvertisements, and returns the corresponding routeAdvertisements object, and an error if there is any.
func (c *routeAdvertisements) Get(ctx context.Context, name string, options metav1.GetOptions) (result *v1.RouteAdvertisements, err error) {
	result = &v1.RouteAdvertisements{}
	err = c.client.Get().
		Resource("routeadvertisements").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of RouteAdvertisements that match those selectors.
func (c *routeAdvertisements) List(ctx context.Context, opts metav1.ListOptions) (result *v1.RouteAdvertisementsList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1.RouteAdvertisementsList{}
	err = c.client.Get().
		Resource("routeadvertisements").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested routeAdvertisements.
func (c *routeAdvertisements) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Resource("routeadvertisements").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a routeAdvertisements and creates it.  Returns the server's representation of the routeAdvertisements, and an error, if there is any.
func (c *routeAdvertisements) Create(ctx context.Context, routeAdvertisements *v1.RouteAdvertisements, opts metav1.CreateOptions) (result *v1.RouteAdvertisements, err error) {
	result = &v1.RouteAdvertisements{}
	err = c.client.Post().
		Resource("routeadvertisements").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(routeAdvertisements).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a routeAdvertisements and updates it. Returns the server's representation of the routeAdvertisements, and an error, if there is any.
func (c *routeAdvertisements) Update(ctx context.Context, routeAdvertisements *v1.RouteAdvertisements, opts metav1.UpdateOptions) (result *v1.RouteAdvertisements, err error) {
	result = &v1.RouteAdvertisements{}
	err = c.client.Put().
		Resource("routeadvertisements").
		Name(routeAdvertisements.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(routeAdvertisements).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *routeAdvertisements) UpdateStatus(ctx context.Context, routeAdvertisements *v1.RouteAdvertisements, opts metav1.UpdateOptions) (result *v1.RouteAdvertisements, err error) {
	result = &v1.RouteAdvertisements{}
	err = c.client.Put().
		Resource("routeadvertisements").
		Name(routeAdvertisements.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(routeAdvertisements).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the routeAdvertisements and deletes it. Returns an error if one occurs.
func (c *routeAdvertisements) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	return c.client.Delete().
		Resource("routeadvertisements").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *routeAdvertisements) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Resource("routeadvertisements").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched routeAdvertisements.
func (c *routeAdvertisements) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.RouteAdvertisements, err error) {
	result = &v1.RouteAdvertisements{}
	err = c.client.Patch(pt).
		Resource("routeadvertisements").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}

// Apply takes the given apply declarative configuration, applies it and returns the applied routeAdvertisements.
func (c *routeAdvertisements) Apply(ctx context.Context, routeAdvertisements *routeadvertisementsv1.RouteAdvertisementsApplyConfiguration, opts metav1.ApplyOptions) (result *v1.RouteAdvertisements, err error) {
	if routeAdvertisements == nil {
		return nil, fmt.Errorf("routeAdvertisements provided to Apply must not be nil")
	}
	patchOpts := opts.ToPatchOptions()
	data, err := json.Marshal(routeAdvertisements)
	if err != nil {
		return nil, err
	}
	name := routeAdvertisements.Name
	if name == nil {
		return nil, fmt.Errorf("routeAdvertisements.Name must be provided to Apply")
	}
	result = &v1.RouteAdvertisements{}
	err = c.client.Patch(types.ApplyPatchType).
		Resource("routeadvertisements").
		Name(*name).
		VersionedParams(&patchOpts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}

// ApplyStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
func (c *routeAdvertisements) ApplyStatus(ctx context.Context, routeAdvertisements *routeadvertisementsv1.RouteAdvertisementsApplyConfiguration, opts metav1.ApplyOptions) (result *v1.RouteAdvertisements, err error) {
	if routeAdvertisements == nil {
		return nil, fmt.Errorf("routeAdvertisements provided to Apply must not be nil")
	}
	patchOpts := opts.ToPatchOptions()
	data, err := json.Marshal(routeAdvertisements)
	if err != nil {
		return nil, err
	}

	name := routeAdvertisements.Name
	if name == nil {
		return nil, fmt.Errorf("routeAdvertisements.Name must be provided to Apply")
	}

	result = &v1.RouteAdvertisements{}
	err = c.client.Patch(types.ApplyPatchType).
		Resource("routeadvertisements").
		Name(*name).
		SubResource("status").
		VersionedParams(&patchOpts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}