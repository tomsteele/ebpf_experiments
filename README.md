# ebpf_experiments

## Install
```
$ sudo apt-get install bpfcc-tools
```

## keyctl

**Install**
```
$ sudo apt-get install libkeyutils-dev
$ sudo apt-get install python3-keyutils
```

**Run**

```
$ sudo python keyctl_snoop.py
```

**Simulate some calls**

```
$ python user_key_sim.py
```

**Output**

```
TIME(s)            COMM             PID    MESSAGE
4752.147166000     b'python3'       8735   b'keyctl_read() - operation 11'
key buffer from keyctl_read(): b'some random secret key'
```
