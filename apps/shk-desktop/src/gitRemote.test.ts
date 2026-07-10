import { describe, expect, it } from "vitest";
import { isSupportedGitRemote } from "./gitRemote";

describe("isSupportedGitRemote", () => {
  it.each([
    "https://github.com/owner/repository.git",
    "ssh://git@github.com/owner/repository.git",
    "git@github.com:owner/repository.git",
  ])("accepts secure remote %s", (remote) => {
    expect(isSupportedGitRemote(remote)).toBe(true);
  });

  it.each([
    "",
    "https://github.com",
    "https://user:token@github.com/owner/repository.git",
    "http://github.com/owner/repository.git",
    "git://github.com/owner/repository.git",
    "file:///tmp/repository.git",
    "--upload-pack=evil",
    "https://github.com/owner/repository.git?token=secret",
  ])("rejects unsupported remote %s", (remote) => {
    expect(isSupportedGitRemote(remote)).toBe(false);
  });
});
