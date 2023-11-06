# python-http-csp
HTTP Content Security Policy Manager

A library to make parsing and generating CSP policies a little easier.

Read more about Content Security Policies: [https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)


## Using this library

Parsing a CSP string:

```python
policy = CSP("default-src 'self';")
```
returns a CSP object with a `default_src` attribute with value `["'self'"]`.

Generating a CSP string:

```python
policy = CSP()
policy.default_src = ["'self'"]
policy.image_src = ["*"]
policy.media_src = ["example.org", "example.net"]
generated_policy = policy.generate()
```
returns a string with the value `default-src 'self'; img-src *; media-src example.org example.net;`.