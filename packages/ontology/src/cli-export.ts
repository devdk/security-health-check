import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { toJsonLd, validateOntology } from './index';

// npm run export -w @shc/ontology  ->  docs/ontology.jsonld
const problems = validateOntology();
if (problems.length > 0) {
  console.error(`Ontology is inconsistent:\n  ${problems.join('\n  ')}`);
  process.exit(1);
}
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const out = path.join(root, 'docs', 'ontology.jsonld');
mkdirSync(path.dirname(out), { recursive: true });
writeFileSync(out, `${JSON.stringify(toJsonLd(), null, 2)}\n`);
console.log(`Wrote ${path.relative(root, out)}`);
