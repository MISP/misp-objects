# KML dataset and KMZ package

The `kml` object describes an original KML XML document or complete KMZ package.
Its attachment preserves source bytes, styles, geometry, extensions and assets.
`source-format` distinguishes KML from KMZ; `entry-document` records the main
KML member inside KMZ, and `archive-member-count` counts file members.

Link extracted observations through `contains` references to existing
`geolocation` objects. Point geometries and nonempty `gx:Track` samples can
become observations. Keep feature IDs, source document paths, folder names,
ExtendedData, raw times, altitude modes and source heights in the observation's
text context when they have no directly compatible typed field.

`placemark-count`, `coordinate-count`, `geometry-type` and bounds cover the
entry document plus locally linked KML members parsed by the producer, with
each document counted once. Coordinate counts include line and polygon
vertices; `observation-count` counts extracted Points and track samples rather
than unique coordinates or all vertices. The attachment remains the complete
source, including unparsed files and unresolved external links.

`start-time`/`end-time` cover complete timezone-qualified times among extracted
observations. Partial dates or timezone-less times should not invent an instant.
Spatial bounds are coordinate extrema rather than a minimum envelope across
the antimeridian. KML sea-level/ground-relative/sea-floor heights must not be
labelled as WGS84 ellipsoid altitude without a vertical-datum conversion.

References: [OGC KML](https://www.ogc.org/standards/kml/) and
[KML reference](https://developers.google.com/kml/documentation/kmlreference).
