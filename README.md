# PerfMon-SoCC

**PerfMon: Performance Monitoring of the Host Network Stack**  
📄 *Accepted at SoCC 2025*

PerfMon is a performance monitoring framework for the host network stack using **eBPF**, enabling fine-grained measurements such as **RTT**, **RNST**, and **CNST** in Kubernetes-based microservice environments.

This project is developed on top of the  
[`netobserv/ebpf-research`](https://github.com/netobserv/ebpf-research) repository, specifically using the `ebpf-measurements` framework.

PerfMon leverages eBPF hook points to monitor packets at ingress and egress points of virtual and external network interfaces in a Kubernetes cluster.

---

## Setup

### 1. Clone the base repository
```bash
git clone https://github.com/netobserv/ebpf-research.git
```
### 2. Navigate to the required directory
```bash
cd ebpf-research/ebpf-measurements/src
```

### 3. Copy the source files 

Copy the source files rtt.c, user.c, and user1.c to ebpf-research/ebpf-measurements/src

### 4. Compile the code
```bash
cd ebpf-research/ebpf-measurements/
make
```
---

## Usage Instructions
To monitor RTT, RNST, and CNST, hook the eBPF code to the ingress and egress of both veth interface and the external interface (the interface via which the cluster node is connected to other cluster nodes).
### 1. Hooking to VETH interface
```bash
./user -i <veth interface name>
```
### 2. Hooking to EXT interface
```bash
./user1 -i <ext interface name>
```
It is mandatory to hook to VETH and EXT interface for the correct monitoring.

