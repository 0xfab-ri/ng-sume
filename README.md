# ng-sume
Mockup driver for NetFPGA SUME on FreeBSD made with iflib(4) using netgraph(4) for RX/TX.

# DANGER
This is an experimental driver for me to play with _iflib_ and to learn how it works in order to write a device driver for NetFPGA SUME sometimes in the future. It is mostly made by copying/pasting the existing code from _ng_eiface(4)_ and _if_em(4)_ thus creating something that kind of works, but panics when something happens (I am not yet sure what that _something_ is).

# Instructions to try
1. Load the module with `make load` - this will create a virtual ngf0 interface.
2. Create an eiface:
```
printf "mkpeer eiface ether ether" | ngctl -f -
printf "name ngeth0: eifc0" | ngctl -f -
```
3. Connect both interfaces:
```
printf "mkpeer eifc0: pipe ether upper" | ngctl -f -
printf "name eifc0:ether pipe" | ngctl -f -
printf "connect pipe: ngf0: lower ether" | ngctl -f -
```
4. Set interfaces:
```
ifconfig ngf0 promisc up
ifconfig ngf0 up

ifconfig ngeth0 name eifc0
ifconfig eifc0 link 00:aa:bb:cc:dd:ee
ifconfig eifc0 promisc up
ifconfig eifc0 inet 10.0.0.1/24 up
```
5. Jail the eiface:
```
jail -c name=out vnet children.max=2 persist
ifconfig eifc0 vnet out
jexec out ifconfig eifc0 10.0.0.1/24 promisc up
```

6. Set the ngf0 and ping:
```
ifconfig ngf0 10.0.0.2/24 promisc up
ping 10.0.0.1
```

7. ???

8. Panic at some point.
