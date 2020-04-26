# ng-sume
Mockup driver for NetFPGA SUME on FreeBSD made with iflib(4) using netgraph(4) for RX/TX.

# DANGER
This is an experimental driver for me to play with _iflib_ and to learn how it works in order to write a device driver for NetFPGA SUME sometimes in the future. It is mostly made by copying/pasting the existing code from _ng_eiface(4)_ and _if_em(4)_ thus creating something that kind of works, but panics when something happens (I am not yet sure what _something_ is).

# NetFPGA SUME reference NIC
For this mockup module, the NetFPGA does not need to be flashed, but here are instructions for flashing it with reference NIC project:
0. install Digilent Adept Tools (Runtime and Utilities) from https://reference.digilentinc.com/reference/software/adept/start
1. build or download the NIC from http://www.cl.cam.ac.uk/research/srg/netos/projects/netfpga/bitfiles/NetFPGA-SUME-live/1.9.0/reference_nic/reference_nic.bit
2. flash the board with:
```
dsumecfg -d NetSUME write -verbose -s 2 -f reference_nic.bit # flash to flash section 2
dsumecfg -d NetSUME setbootsec -s 2 # load flash section 2 on board boot-up
dsumecfg -d NetSUME reconfig -s 2 # reconfigure the board from section 2
```

# Instructions to try ng-sume
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
ifconfig ngeth0 name eifc0
```
4. Jail the eiface:
```
jail -c name=out vnet children.max=2 persist
ifconfig eifc0 vnet out
jexec out ifconfig eifc0 10.0.0.1/24 promisc up
```

5. Set the ngf0 and ping:
```
ifconfig ngf0 10.0.0.2/24 promisc up
ping 10.0.0.1
```

6. ???

7. Panic at some point.
