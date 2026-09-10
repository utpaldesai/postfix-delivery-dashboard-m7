# Third-Party Licenses / EULA

Most components are open-source and are governed by software licenses rather than proprietary EULAs.

This directory contains:
- `DECLARED-COMPONENTS.csv`
- `THIRD-PARTY-NOTICES.md`
- common license texts
- Python package-specific license files
- `collect-runtime-licenses.sh` for exact built-image Debian/Python licenses

The exact Debian and pip transitive dependency set is resolved during image build. Run the collector after each production build.

No license was supplied for the dashboard's own original source; see `PROJECT-LICENSE-NOT-SPECIFIED.txt`.
