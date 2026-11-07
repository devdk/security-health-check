import type { Confidence, SoftwareType } from '@shc/shared';
import type { ComponentFact } from './types';

const STRENGTH: Record<Confidence, number> = { possible: 1, likely: 2, confirmed: 3 };

/**
 * The software the scan has found so far. Several modules can report the same component;
 * facts are merged, and the best-supported version wins.
 */
export class ComponentStore {
  private readonly items = new Map<string, ComponentFact>();

  private key(type: SoftwareType, slug: string): string {
    return `${type}:${slug}`;
  }

  add(fact: ComponentFact): ComponentFact {
    const key = this.key(fact.type, fact.slug);
    const existing = this.items.get(key);
    if (!existing) {
      const copy = { ...fact, sources: [...new Set(fact.sources)] };
      this.items.set(key, copy);
      return copy;
    }
    existing.sources = [...new Set([...existing.sources, ...fact.sources])];
    existing.name ??= fact.name;
    if (fact.active !== undefined) existing.active = fact.active;
    if (fact.version) {
      const incoming = STRENGTH[fact.versionConfidence ?? 'possible'];
      const current = existing.version ? STRENGTH[existing.versionConfidence ?? 'possible'] : 0;
      if (incoming > current) {
        existing.version = fact.version;
        existing.versionConfidence = fact.versionConfidence ?? 'possible';
      }
    }
    return existing;
  }

  get(type: SoftwareType, slug: string): ComponentFact | undefined {
    return this.items.get(this.key(type, slug));
  }

  list(type?: SoftwareType): ComponentFact[] {
    const all = [...this.items.values()];
    return type ? all.filter((c) => c.type === type) : all;
  }
}
