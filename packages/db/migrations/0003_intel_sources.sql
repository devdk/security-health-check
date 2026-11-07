CREATE TABLE "software_releases" (
	"software_type" "software_type" NOT NULL,
	"slug" text NOT NULL,
	"latest_version" text,
	"found" boolean DEFAULT true NOT NULL,
	"details" jsonb,
	"fetched_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "software_releases_pkey" PRIMARY KEY("software_type","slug")
);
--> statement-breakpoint
ALTER TABLE "vuln_cache" ADD COLUMN "informational" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "vuln_cache" ADD COLUMN "description" text;--> statement-breakpoint
ALTER TABLE "vuln_cache" ADD COLUMN "remediation" text;--> statement-breakpoint
ALTER TABLE "vuln_cache" ADD COLUMN "cwe" jsonb;--> statement-breakpoint
ALTER TABLE "vuln_cache" ADD COLUMN "record_url" text;--> statement-breakpoint
ALTER TABLE "vuln_cache" ADD COLUMN "copyrights" jsonb;