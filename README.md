To start unbound
 docker run --rm -ti -e SO_REUSEPORT=yes -e DO_IPv6=no -e VERBOSITY=0 --net=host private/unbound

To build unbound
 docker build --network=host -t private/unbound .

To start
 ./rvz >~/.rvz.log 2>&1

---
[![UNLICENSE](noc.png)](UNLICENSE)

