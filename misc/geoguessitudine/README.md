# GeoGuessitUdine [_snakeCTF 2025 Finals_]

**Category**: misc
**Author**: michelelizzit

## Description

Geoguess it. It's easy. It's in the Udine province.

We have found a place full of snakes. We sent our photographer to take a picture, but he got lost.
He sent us two pictures, can you locate where the first one was taken?

## Solution

In Picture 1 we see that we are in a mountain area. We also see that we are near:
 - a public substation connected to an aerial 20kv line
 - a playground
 - a drinking water fountain
In Picture 2 we also see a nearby church.

Go to [Overpass](https://overpass-turbo.eu/).  
Write a query to find a place matching the above mentioned features.

```
[out:json][timeout:25];

area
  ["boundary"="administrative"]
  ["admin_level"="6"]
  ["name:fur"="Udin"]
  ->.udine;

(
  node["power"~"substation|transformer"](area.udine);
  way ["power"~"substation|transformer"](area.udine);
)->.p;

(
  node    ["historic"="monument"](area.udine);
  way     ["historic"="monument"](area.udine);
  relation["historic"="monument"](area.udine);
)->.m;

(
  node    ["amenity"="drinking_water"](area.udine);
  way     ["amenity"="drinking_water"](area.udine);
  relation["amenity"="drinking_water"](area.udine);
)->.drink;

(
  node    ["leisure"="playground"](area.udine);
  way     ["leisure"="playground"](area.udine);
  relation["leisure"="playground"](area.udine);
)->.playgrounds;

nwr.playgrounds(around.drink:50)->.s1;
nwr.s1(      around.m:50    )->.s2;
nwr.s2(      around.p:50    )->.result;

(
  .result;
);
out body;
>;
out skel qt;
```