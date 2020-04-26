This is a test program I wrote to figure out how to get Envoy to automatically reload certificates
from k8s secrets. I did make it work and wrote a blog post about it:
https://jrock.us/posts/rotating-envoy-certs/

If you are also trying to get it to work, you may find screwing around with `main.go` to be easier
than screwing around in production. Have fun!
