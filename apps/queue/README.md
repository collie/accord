# How to running queue

1. Please install accord.
2. run as follows

```
	$ make apps
	$ ./apps/qbench localhost 9090 200 10000
	2000000 requests in 298.100236 sec. (6709.15 throughput)
```

## Bencmark result

* The benchmark environment
 * Xeon 2.1 GHz 4 Core
 * 7200 rpm HDD
 * Run Accord as disk persistency mode with single node

the result of the benchmarks(50% push and 50% pop) is as follows:

```
	2000000 requests in 298.100236 sec. (6709.15 throughput)
```


Additionally, the other benchmarks(100% push) achieve better result as follows:

```
	2000000 requests in 167.953943 sec. (11908.03 throughput)
```

To benchmark only push(), please comment out queue_pop() function in the run() function.

## TODO

* run benchmark with 1KB message
