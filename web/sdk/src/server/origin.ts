/** The gateway origin without trailing slashes. A loop, not `/\/+$/`: the regex backtracks on a
 * long run of slashes and code scanning flags it on every call site. */
export function stripTrailingSlashes(origin: string): string {
  let end = origin.length;
  while (end > 0 && origin.charCodeAt(end - 1) === 47 /* "/" */) end -= 1;
  return origin.slice(0, end);
}
