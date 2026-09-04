# AndroidLibXrayLite

## Build requirements
* JDK
* Android SDK
* Go
* gomobile

## Build instructions
1. `git clone [repo] && cd AndroidLibXrayLite`
2. `gomobile init`
3. `go mod tidy -v`
4. `gomobile bind -v -androidapi 21 -trimpath -ldflags='-s -w -buildid= -checklinkname=0' ./`

## Documentation
* [README_fetch.md](README_fetch.md) — `FetchWeb` / `ResolveDoH`: HTTP and DoH fetching with TLS fragmentation, ECH and uTLS fingerprints. Options JSON reference plus Android and Go usage.
