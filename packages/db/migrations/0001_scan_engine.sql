CREATE TYPE "public"."confidence" AS ENUM('confirmed', 'likely', 'possible');--> statement-breakpoint
ALTER TYPE "public"."software_type" ADD VALUE 'web_server';--> statement-breakpoint
CREATE TABLE "site_components" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"scan_id" uuid NOT NULL,
	"site_id" uuid NOT NULL,
	"software_type" "software_type" NOT NULL,
	"slug" text NOT NULL,
	"name" text,
	"version" text,
	"version_confidence" "confidence",
	"sources" text[] DEFAULT '{}'::text[] NOT NULL,
	"active" boolean,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "site_components_scan_item_key" UNIQUE("scan_id","software_type","slug")
);
--> statement-breakpoint
ALTER TABLE "findings" ADD COLUMN "concept_id" text NOT NULL;--> statement-breakpoint
ALTER TABLE "findings" ADD COLUMN "component_id" uuid;--> statement-breakpoint
ALTER TABLE "findings" ADD COLUMN "confidence" "confidence" DEFAULT 'confirmed' NOT NULL;--> statement-breakpoint
ALTER TABLE "scans" ADD COLUMN "base_url" text;--> statement-breakpoint
ALTER TABLE "scans" ADD COLUMN "module_results" jsonb;--> statement-breakpoint
ALTER TABLE "scans" ADD COLUMN "ontology_version" text;--> statement-breakpoint
ALTER TABLE "site_components" ADD CONSTRAINT "site_components_scan_id_scans_id_fk" FOREIGN KEY ("scan_id") REFERENCES "public"."scans"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "site_components" ADD CONSTRAINT "site_components_site_id_sites_id_fk" FOREIGN KEY ("site_id") REFERENCES "public"."sites"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "site_components_site_lookup_idx" ON "site_components" USING btree ("site_id","software_type","slug");--> statement-breakpoint
ALTER TABLE "findings" ADD CONSTRAINT "findings_component_id_site_components_id_fk" FOREIGN KEY ("component_id") REFERENCES "public"."site_components"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "findings_concept_idx" ON "findings" USING btree ("concept_id");