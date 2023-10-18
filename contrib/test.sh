#!/bin/bash

test() {
    export OVN_HYBRID_OVERLAY_ENABLE=true
    export OVN_MULTICAST_ENABLE=true
    export OVN_EMPTY_LB_EVENTS=true
    export OVN_HA=true
    export OVN_DISABLE_SNAT_MULTIPLE_GWS=false
    export KIND_INSTALL_METALLB=true
    export OVN_GATEWAY_MODE=shared
    export OVN_SECOND_BRIDGE=false
    export KIND_IPV4_SUPPORT=true
    export KIND_IPV6_SUPPORT=false
    export ENABLE_MULTI_NET=false
    export KIND_INSTALL_KUBEVIRT=false
    export OVN_COMPACT_MODE=false
    export OVN_DUMMY_GATEWAY_BRIDGE=false
    export OVN_ENABLE_INTERCONNECT=false
    export KIND_INSTALL_INGRESS=true
    export KIND_ALLOW_SYSTEM_WRITES=true
    export OVN_DISABLE_SNAT_MULTIPLE_GWS=true
  
    ./kind.sh
  
    # workaround for my old docker version
    kind export kubeconfig --name ovn
    kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/main/config/manifests/metallb-native.yaml
    kubectl wait --for=condition=ready -n metallb-system pod -l component=controller --timeout 300s && kubectl apply -f - <<EOF
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: dev-env-bgp
  namespace: metallb-system
spec:
  addresses:
  - 192.168.10.0/24
  - fc00:f853:0ccd:e799::/124
EOF
  
    make -C ../test/ control-plane
    [ $? = 0 ] || break
}

while true; do
    kind delete cluster --name ovn
    rm -rf ../go-controller/_output
    rm -rf metallb
    rm -rf ../test/_artifacts
    date=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    echo "Testing $date"
    log=$(mktemp run.${date}.XXX)
    test >> $log 2>&1
    echo "Test done at $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
done
