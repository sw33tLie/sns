# sns
IIS shortname scanner written in Go

## Installation
Make sure you've a recent version of the Go compiler installed on your system. Then just run:

```
go install github.com/sw33tLie/sns@latest
```

## Usage
```
sns -u https://example.com/
```
View all available flags with `sns -h`.

## References

- https://soroush.secproject.com/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf
- https://soroush.secproject.com/blog/2014/08/iis-short-file-name-disclosure-is-back-is-your-server-vulnerable/
- https://soroush.secproject.com/blog/2012/06/microsoft-iis-tilde-character-vulnerabilityfeature-short-filefolder-name-disclosure/
