# BBN Curveball

Fork of the open source releases of the BBN Curveball project.

## Caveats

This implementation of the Curveball protocols (including the
TLS and HTTP Rebound protocols) has several known shortcomings
that make it easy to detect and block.  These shortcomings are not
intrinsic to the protocols, but reflect the fact that the
implementation was intended to be tested against assumptions
that were valid in 2010-2012, but are no longer valid.

See the issues for a description of things that would need
to be fixed in order to make Curveball usable at the current
time.

## History

The initial commits of this repository contain the open source
releases that were originally published on
[curveball.nct.bbn.com](https://curveball.nct.bbn.com/).
There is a tag for each of the releases:

 * **bbn-curveball-2017.05.23** - An experimental release with changes
    to use a different click platform, to enable running at 10Gbps or
    faster.  Also some items were renamed, and minor bugfixing.

    This release _does not_ have nearly the same level of packaging
    and documentation as the earlier releases.  It is a snapshot of
    an experiment in progress at the moment when development was
    mothballed, at least temporarily, rather than a "real" release
    like the others.

    Note that this tag is on a branch off of master, rather than
    directly on master.  These changes will not be merged back to
    master until they have been reviewed properly and tested on
    proper hardware (which I admit might not actually ever happen).

 * **bbn-curveball-2017.05.12** - A minor update to to 2016.03.08 release,
    to fix a problem that the fake CA and certificates we used for
    our example had expired, as well as the fake "Curveball" certificate
    itself.

    This is a problem that will happen repeatedly until we do
    something more intelligent about our test scripts.

    Note that nobody should be using this CA or any of the certificates
    it has signed anywhere outside of a closed testbed.  They're all
    totally bogus, and the signing key is public knowledge (i.e.
    it's in the repo you're looking at).

 * **bbn-curveball-2016.03.08** - Cleanups and tweaks.  Many of the
    changes here were related to running the benchmarks used for the
    Rebound paper.

 * **bbn-curveball-2014.12.19** - The end-of-program Curveball release,
    marking the end of the original program that Curveball was 
    part of.

 * **bbn-curveball-2014.06.18** - The initial open source Curveball release.

## Contributors

Curveball was conceived, designed, implemented, tested, and supported
by a number of people at Raytheon BBN Technologies over the
course of the project.  I hope to have a complete list here at some
point, after I get permission from people to mention their names.
