Here are my samples.

Please don't worry too much about class names, etc.
I'm sure you understand that all of this is a small step above pseudocode, and simply exists to try and clarify why I like the pattern I'm advocating.

I recommend looking at them in the following order:

* _singlekey_ - This sample is a likely candidate for how REST APIs will think about the encoder, i.e. many will just use a single key.
Its intent is to act as a baseline for the other two samples, but it also hopefully demonstrates that NimbusJwtEncoder has an opinion about
headers and claims that cannot be overridden.
* _context_ - This sample shows the value of an encoder contract that makes it possible to expose the underlying library, which is handy in Nimbus's case because it allows callers to supply an instance of `SecurityContext`.
The proposed NimbusJWSMinter, for example, supports handing a `JWKSecurityContext` so that a key can be specified.
* _style_ - This sample shows that returning a builder-like object is flexible enough to support both approaches - either customization before or after, while the approach in the PR is only practical for setting the values before the call.
Obviously, style is a lower priority, but if one way can address both approaches, why wouldn't we pick that, all other things being equal?

In each case, there are four classes:

* `TokenConfigOne` - what I'd imagine a typical `JwtEncoder` configuration to be where the application wants to set some defaults
* `TokenControllerOne` - how I'd imagine a controller using `JwtEncoder` to mint a `Jwt`, removing the defaulted `crit` header at invocation time
* `TokenConfigTwo` - what I'd imagine a typical `JwtEncoderAlternative` configuration to be where the application wants to set some defaults
* `TokenControllerTwo` - how I'd imagine a controller using `JwtEncoderAlternative` to mint a `Jwt`, removing the defaulted `crit` header at invocation time

### Usage

And you can get a token by doing:

```bash
http -a user:password :8080/token/one
http -a user:password :8080/token/two
```

You can of course run the `XXXApplicationTests` tests, too.

### Other Notes

The reason there are unit tests for `JwtEncoderAlternative` are not because I'm wanting to take over the PR, but only because as I was doing my research, I wanted to make it really clear to myself the ins and outs of the pattern.
You are welcome to play around with those tests as well, if you wish.

I understand your concerns about mixing responsibilities.
I don't see it this way - that information needs to be specified either way, it's simply a matter of when.
As you can see, the implementation doesn't do any additional work - it simply changes how it accepts it from the caller.
In fact, just as a point of illustration, I added an `apply` method to show that the responsibility could also be delegated to component objects.

By the way, thank you for the observation about prototype beans.
Honestly, that brought me much closer to "even" in my assessment of the two approaches.
For the reasons each of these samples show, I still lean towards returning a builder-like object.

### Conclusions

If you are still not convinced after going through these samples, it might be time to get a third point of view from Rob.
Actually, we've debated this point long enough it might be good to get his opinion regardless.
I won't be offended if I'm out-voted.

