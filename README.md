# PerfMon-SoCC

**PerfMon: Performance Monitoring of the Host Network Stack**  
📄 *Accepted at SoCC 2025*

PerfMon is a performance monitoring framework for the host network stack using **eBPF**, enabling fine-grained measurements such as **RTT**, **RNST**, and **CNST** in Kubernetes-based microservice environments.

> 🚧 **Note:** Code will be released soon.

---

## Overview

This project is developed on top of the  
[`netobserv/ebpf-research`](https://github.com/netobserv/ebpf-research) repository, specifically using the `ebpf-measurements` framework.

PerfMon leverages eBPF hook points to monitor packets at ingress and egress points of virtual and external network interfaces in a Kubernetes cluster.

---

## Repository Setup

### 1. Clone the base repository
```bash
git clone https://github.com/netobserv/ebpf-research.git
```
## Navigate to the required directory


# PerfMon-SoCC
SoCC 2025 - PerfMon: Performance Monitoring of Host Network Stack

Code is coming soon!

We developed our code on top of netobserv/ebpf_research repo. 

Clone the repo https://github.com/netobserv/ebpf-research/tree/main/ebpf-measurements. 

Navigate to ebpf-research/ebpf-measurements/src/. 

Copy the code rtt.c, user.c and user1.c to the directory. 

Compile the code from ebpf-research/ebpf-measurements/ by issuing make command. 

After deploying the microservice application in the Kubernetes cluster, achieve RTT, RNST, and CNST monitoring by adding ebpf hooks points as given below. 
To hook the code to the ingress and egress of a particular veth-interface, execute using "sudo ./user -i <veth interface> ". 

To hook the code to the external interface (the interface via which the node is connected to other cluster nodes), execute "sudo ./user1 -i <veth interface>". It is mandatory to hook to the external interface.

