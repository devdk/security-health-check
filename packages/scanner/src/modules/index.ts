import type { CheckModule } from '../types';
import { adminExposure } from './admin-exposure';
import { directoryListing } from './directory-listing';
import { exposedFiles } from './exposed-files';
import { securityHeaders } from './headers';
import { outdatedSoftware } from './outdated-software';
import { phpVersion } from './php-version';
import { pluginsThemes } from './plugins-themes';
import { tlsCheck } from './tls';
import { userEnum } from './user-enum';
import { vulnMatch } from './vuln-match';
import { wpDetect } from './wp-detect';
import { xmlrpc } from './xmlrpc';

export {
  adminExposure,
  directoryListing,
  exposedFiles,
  outdatedSoftware,
  phpVersion,
  pluginsThemes,
  securityHeaders,
  tlsCheck,
  userEnum,
  vulnMatch,
  wpDetect,
  xmlrpc,
};

/** Every check the scanner runs (stages decide sequencing). */
export const ALL_MODULES: readonly CheckModule[] = [
  // stage 1: gather facts from the site
  wpDetect,
  pluginsThemes,
  phpVersion,
  exposedFiles,
  userEnum,
  xmlrpc,
  directoryListing,
  tlsCheck,
  securityHeaders,
  adminExposure,
  // stage 2: analyse what stage 1 found (no requests to the site)
  vulnMatch,
  outdatedSoftware,
];
