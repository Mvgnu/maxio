import { describe, expect, it } from "bun:test";

import { buildHashRoute, parseHashRoute } from "./navigation";

describe("navigation route helpers", () => {
  it("parses root and metrics routes", () => {
    expect(parseHashRoute("")).toEqual({
      bucket: null,
      view: "objects",
      prefix: "",
    });
    expect(parseHashRoute("#/metrics")).toEqual({
      bucket: null,
      view: "metrics",
      prefix: "",
    });
  });

  it("parses bucket settings and object-prefix routes", () => {
    expect(parseHashRoute("#/photos/settings")).toEqual({
      bucket: "photos",
      view: "settings",
      prefix: "",
    });

    expect(parseHashRoute("#/photos/folder/nested")).toEqual({
      bucket: "photos",
      view: "objects",
      prefix: "folder/nested",
    });
  });

  it("decodes encoded bucket names", () => {
    expect(parseHashRoute("#/bucket%20name/path")).toEqual({
      bucket: "bucket name",
      view: "objects",
      prefix: "path",
    });
  });

  it("builds hash routes from view state", () => {
    expect(buildHashRoute("metrics", null, "")).toBe("/metrics");
    expect(buildHashRoute("objects", null, "")).toBe("/");
    expect(buildHashRoute("objects", "bucket name", "")).toBe(
      "/bucket%20name"
    );
    expect(buildHashRoute("objects", "bucket name", "a/b")).toBe(
      "/bucket%20name/a/b"
    );
    expect(buildHashRoute("settings", "bucket name", "")).toBe(
      "/bucket%20name/settings"
    );
  });
});
