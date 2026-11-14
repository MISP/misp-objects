# NMEA 0183 receiver log

The `nmea` object preserves an NMEA 0183 log as an attachment, with hashes,
file metadata, sentence and extracted-position counts, talker identifiers,
and spatial/temporal bounds. It describes a dataset rather than a receiver's
identity or the reliability of its measurements.

Use `contains` object references to link extracted `geolocation` observations.
Their WGS84 latitude/longitude and observation times can be queried independently.
Keep each sentence's type, talker, source line, time-of-day, fix quality,
satellites, HDOP and other receiver metadata in the observation's `text` context
when no dedicated typed field exists. HDOP is not an accuracy radius.

`position-count` counts extracted observations, not unique coordinates or fused
receiver fixes. For example, active GGA and RMC sentences for the same instant
may produce two observations. `invalid-fix-count` counts position sentences
reporting an invalid/no fix. `unhandled-sentence-count` counts sentences whose
payload was retained without interpretation; interpreted time/datum sentences
need not contribute to that count.

`start-time` and `end-time` cover extracted positions with dates known from the
log. Time-of-day alone does not establish a date. Spatial bounds are coordinate
extrema, not a minimum envelope across the antimeridian. The attachment remains
the complete source, including unhandled records and original ordering.

GGA altitude above mean sea level must not be labelled as ellipsoid altitude:
when both values are available in metres, ellipsoid height is MSL height plus
geoid separation. Keep the original values in observation context.

Reference: [GPSD's NMEA sentence descriptions](https://gpsd.io/NMEA.html).
