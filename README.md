INTRODUCTION
============
Quick hacky script to generate an Amazon AWS-accepted SSL chain ( used by ELBs and Cloudfront ).

USAGE
=====

./aws-ssl-chain-finder.py cert-file chain-dr

EXAMPLES
========

Where chain dir contains potential certificate chain files in .crt format.
And cert.crt is the certificate you are trying to find the chain for:

    ./aws-ssl-chain-finder.py cert.crt chain > chain.crt

chain.crt should then be accepted by Amazon AWS as a valid chain.