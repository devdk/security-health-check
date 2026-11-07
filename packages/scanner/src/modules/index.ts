import type { CheckModule } from '../types';
import { pluginsThemes } from './plugins-themes';
import { vulnMatch } from './vuln-match';
import { wpDetect } from './wp-detect';

export { pluginsThemes, vulnMatch, wpDetect };

/** Every check the scanner runs, in no particular order (stages decide sequencing). */
export const ALL_MODULES: readonly CheckModule[] = [wpDetect, pluginsThemes, vulnMatch];
