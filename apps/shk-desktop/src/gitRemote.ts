export function isSupportedGitRemote(value: string): boolean {
  const remote = value.trim();
  if (!remote || /\s|[?#]/.test(remote) || remote.startsWith("-")) return false;

  if (remote.startsWith("https://")) {
    const rest = remote.slice("https://".length);
    const authority = rest.split("/", 1)[0];
    return Boolean(authority) && !authority.includes("@") && rest.includes("/");
  }

  if (remote.startsWith("ssh://")) {
    return remote.slice("ssh://".length).includes("/");
  }

  const separator = remote.indexOf(":");
  return separator > 0 && remote.slice(0, separator).includes("@") && separator < remote.length - 1;
}
