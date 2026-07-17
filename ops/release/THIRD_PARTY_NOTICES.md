# Third-party notices for the release image

The release blueprint uses one external runtime dependency: the Docker
Official Image for Python, observed as `python:3.11.14-slim-bookworm` and
pinned to `docker.io/library/python@sha256:65a93d69fa75478d554f4ad27c85c1e69fa184956261b4301ebaf6dbb0a3543d`
for `linux/amd64`.

Upstream provenance is the Docker Official Images `library/python` definition
and the Python source distribution. Python is distributed under the Python
Software Foundation License Version 2 and its bundled component licenses. The
complete Python license text remains installed in the image at
`/usr/local/lib/python3.11/LICENSE.txt`.

The slim image contains Debian Bookworm binary packages. Their exact versions
are transitively frozen by the image digest and are enumerated into the release
SBOM before a ReleaseManifest may be issued. Package copyright and license
texts remain installed at `/usr/share/doc/*/copyright`. No package is installed
by this repository's Containerfile, and the runtime has no network authority.

This notice does not change the licensing status of this repository.
