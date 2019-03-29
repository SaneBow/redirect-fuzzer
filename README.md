# redirect-fuzzer
Fuzzing script for redirect URL validator

## Usage

```
usage: fuzz.py [-h] [-u URL] [--cookie-file FILE] [--endpoint URL]
               [--client-id ID] [--redirect-uri URL] [--interval SECONDS]
               [--verbose]

Online URL Validator Fuzzer.

optional arguments:
  -h, --help          show this help message and exit
  -u URL, --url URL   Full request URL
  --cookie-file FILE  File containing raw Cookie header string

advanced options:
  --endpoint URL      Specify authorize endpoint
  --client-id ID      Specify client_id
  --redirect-uri URL  Specify redirect_uri
  --interval SECONDS  Set delay between each fuzzing request
  --verbose           Enable verbose output
```

exmaple:
```
python fuzz.py -u 'http://idp.com/authorize?response_type=code&client_id=1234&redirect_uri=http://rp.com/callback' --cookie-file=cookie.txt
```
