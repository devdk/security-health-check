import { Type, type Static, type TSchema } from 'typebox';
import { Value } from 'typebox/value';

/** Largest report body the API accepts. A site with 1000 plugins stays well under it. */
export const REPORT_MAX_BYTES = 512 * 1024;
export const REPORT_SCHEMA_VERSION = 1;

const strict = <T extends Record<string, TSchema>>(props: T) => Type.Object(props, { additionalProperties: false });
const nullable = <T extends TSchema>(schema: T) => Type.Union([schema, Type.Null()]);
const Text = (maxLength: number) => Type.String({ maxLength, pattern: '^[^\\u0000-\\u001f]*$' });
const Version = Type.String({ minLength: 1, maxLength: 64, pattern: '^[0-9A-Za-z.+_-]+$' });
const Slug = Type.String({ minLength: 1, maxLength: 200, pattern: '^[A-Za-z0-9._-]+$' });
const Role = Type.String({ minLength: 1, maxLength: 64, pattern: '^[A-Za-z0-9_-]+$' });
const IsoTime = Type.String({ maxLength: 40, pattern: '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[+-]\\d{2}:\\d{2})$' });
const HttpUrl = Type.String({ maxLength: 2000, pattern: '^https?://[^\\s]+$' });
/** Relative to the root its list names; never absolute, never a control character. */
const RelPath = Type.String({ minLength: 1, maxLength: 500, pattern: '^[^/\\u0000-\\u001f][^\\u0000-\\u001f]*$' });
const Count = Type.Integer({ minimum: 0, maximum: 10_000_000 });
const Bytes = Type.Integer({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER });
const pathList = Type.Array(RelPath, { maxItems: 100 });

export const InsideReportSchema = strict({
  schema: Type.Literal(REPORT_SCHEMA_VERSION),
  generatedAt: IsoTime,
  plugin: strict({ version: Version }),
  site: strict({ homeUrl: HttpUrl, siteUrl: HttpUrl, multisite: Type.Boolean() }),
  wordpress: strict({ version: Version, locale: Type.String({ maxLength: 20, pattern: '^[A-Za-z0-9_-]*$' }) }),
  php: strict({ version: Version }),
  plugins: Type.Array(
    strict({
      slug: Slug,
      /** Plugin basename, e.g. "contact-form-7/wp-contact-form-7.php". */
      file: RelPath,
      name: Text(300),
      version: nullable(Version),
      active: Type.Boolean(),
      autoUpdate: Type.Boolean(),
    }),
    { maxItems: 1000 },
  ),
  themes: Type.Array(
    strict({ slug: Slug, name: Text(300), version: nullable(Version), active: Type.Boolean(), parent: nullable(Slug), autoUpdate: Type.Boolean() }),
    { maxItems: 200 },
  ),
  /** Accounts with the administrator role. Logins arrive masked; the full name never leaves the site. */
  admins: Type.Array(strict({ login: Text(64), roles: Type.Array(Role, { maxItems: 20 }) }), { maxItems: 500 }),
  debug: strict({ wpDebug: Type.Boolean(), wpDebugDisplay: Type.Boolean(), wpDebugLog: Type.Boolean(), displayErrors: Type.Boolean() }),
  configFile: strict({
    found: Type.Boolean(),
    location: nullable(Type.Union([Type.Literal('root'), Type.Literal('parent')])),
    /** Octal permission bits such as "0644"; null where the host has no POSIX permissions. */
    mode: nullable(Type.String({ pattern: '^0[0-7]{3,4}$' })),
  }),
  /** Core files compared with WordPress.org checksums; paths relative to the WordPress root. */
  coreIntegrity: strict({
    status: Type.Union([Type.Literal('ok'), Type.Literal('unavailable')]),
    reason: nullable(Text(300)),
    modified: pathList,
    missing: pathList,
    /** PHP files inside wp-admin or wp-includes that WordPress doesn't ship. */
    unexpected: pathList,
    truncated: Type.Boolean(),
  }),
  /** PHP files under the uploads folder; paths relative to it. */
  uploadsPhp: strict({
    files: Type.Array(strict({ path: RelPath, size: Bytes, modifiedAt: IsoTime }), { maxItems: 100 }),
    scanned: Count,
    truncated: Type.Boolean(),
  }),
  /** PHP files in wp-content changed in the last `days` days; paths relative to wp-content. */
  recentPhp: strict({
    days: Type.Integer({ minimum: 1, maximum: 90 }),
    files: Type.Array(strict({ path: RelPath, modifiedAt: IsoTime, packageUpdated: Type.Boolean() }), { maxItems: 100 }),
    truncated: Type.Boolean(),
  }),
});

export type InsideReport = Static<typeof InsideReportSchema>;

export type ParseResult = { ok: true; report: InsideReport } | { ok: false; errors: string[] };

/** The boundary check for everything a plugin sends. Unknown fields are refused, not ignored. */
export function parseInsideReport(value: unknown): ParseResult {
  if (Value.Check(InsideReportSchema, value)) return { ok: true, report: value };
  const errors = [...Value.Errors(InsideReportSchema, value)].slice(0, 10).map((e) => `${e.instancePath || '/'} ${e.message}`);
  return { ok: false, errors };
}
