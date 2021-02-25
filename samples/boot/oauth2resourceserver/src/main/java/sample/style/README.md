The point of this sample is to show that returning a builder is ultimately more flexible since it allows for both styles.

In this case,

* `TokenConfigOne` is enforcing its opinion in a delegating `JwtEncoder` implementation, and
* `TokenConfigTwo` is enforcing its opinion using `JoseHeader.Builder` and `JwtClaimsSet.Builder` beans

(this is the opposite arrangement from the other samples)

When the tables are turned like this, `TokenConfigTwo` and `TokenControllerTwo` are equally complex as in the other samples.
But, `TokenConfigOne` and `TokenControllerOne` are more complex and are missing features.

I completely respect the fact that you prefer customizing outside of the encoder, and my point is not to discount that.
It seems to me that returning a builder leaves the possibility open for either style.
