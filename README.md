# Sunlight Woodpecker

This is a port of ct-woodpecker for Sunlight. Because there's no merge delay, it is considerably simpler, with no
persistent storage or searching the tree required.

It generates certificates and precertificates and submits them to a CT log. It checks that the submitted entry is in the
log at the position the SCT claims.
