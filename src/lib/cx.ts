export type ClassValue = string | false | null | undefined;

/** Join conditional class names. */
export function cx(...values: ClassValue[]): string {
  return values.filter((value): value is string => Boolean(value)).join(" ");
}
