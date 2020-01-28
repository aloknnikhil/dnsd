# dnsd
A DNS daemon to spoof A record -> IP resolution

## Build
```sh
make
```

## Run
```sh
./dnsd -e foo.com/192.168.1.33 bar.com/99.22.1.33
```

## Test
```sh
make check
```
