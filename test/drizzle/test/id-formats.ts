/**
 * User id formats the Drizzle schemas are generated for: Better Auth's default random text ids,
 * `generateId: "uuid"` (Postgres `uuid` columns) and `generateId: "serial"` (integer columns).
 */
export const ID_FORMATS = ["text", "uuid", "serial"] as const;

export type IdFormat = (typeof ID_FORMATS)[number];
